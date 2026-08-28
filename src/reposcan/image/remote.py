# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Module for working with remote images."""

import logging
from typing import Protocol

from reposcan.execution.process import Failure, run_process, succeeded
from reposcan.image import cache

logger = logging.getLogger(__name__)

# The `canonical` shorthand: the image reposcan publishes to GHCR (see the
# publish-image workflow). A user can configure `canonical` instead of the full ref.
CANONICAL_SHORTHAND = "canonical"
CANONICAL_REF = (
    "ghcr.io/canonical/reposcan@sha256:"
    "4c6a1d4eab499dd0a2a66386ac6fb34aff10020f116fd996d4a4fb50511672bf"
)

# build the tool image locally instead of pulling the default.
LOCAL_BUILD_SHORTHAND = "build"


def resolve_remote_ref(value: str) -> str:
    """The image reference for a configured `image` value.

    Returns:
        The canonical published image for the `canonical` shorthand, otherwise the value
        unchanged. The `build` shorthand is not a remote ref and is handled by the
        caller (it means "build locally, do not pull").
    """
    return CANONICAL_REF if value == CANONICAL_SHORTHAND else value


def is_digest_pinned(ref: str) -> bool:
    """True if `ref` pins a specific image content by digest (name@sha256:...).

    Returns:
        The docker client verifies such a ref on pull, so it needs no trust-on-first-use
        record.
    """
    return "@sha256:" in ref


class ImagePuller(Protocol):
    """Pulls a published image for one backend and reports its content id."""

    name: str

    def pull(self, ref: str) -> Failure | None:
        """Fetch `ref` from its registry. None on success, or a Failure."""
        ...

    def identity(self, ref: str) -> str | None:
        """The content id of the pulled image `ref`, or None if it is not present."""
        ...


class DockerRemote:
    """Pulls published images with the docker CLI."""

    name = "docker"

    def pull(self, ref: str) -> Failure | None:
        result = run_process(
            ["docker", "pull", ref], check=True, stream_stdout=True, stream_stderr=True
        )
        return result if isinstance(result, Failure) else None

    def identity(self, ref: str) -> str | None:
        argv = ["docker", "image", "inspect", "--format", "{{.Id}}", ref]
        result = run_process(argv, timeout=30)
        if succeeded(result):
            return result.stdout.strip() or None
        return None


def ensure_pulled(puller: ImagePuller, ref: str) -> str | Failure:
    """Pull `ref` and return the reference to run, or a Failure.

    If the `ref` is digest-hash-pinned (e.g., ghcr.io/org/name@sha256:...), we
    check for and re-use the image if already pulled. Notably, the digest-hash is NOT
    the same hash we see locally with `docker image inspect`; this hash is the "config
    hash", which transitively includes hashes of each container filesystem layer.
    The mapping of digest-hash to config-hash is created by docker when pulling the
    image.

    A tag-only ref is pinned on first use and -- on later pulls -- refused if its
    content id no longer matches what was first recorded. It is always pulled over the
    network to ensure we catch changes (i.e., a new :latest tag).

    Args:
        puller: The backend puller that fetches the image and reports its content id.
        ref: The image reference to pull.

    Returns:
        The reference to run, or a Failure if the pull failed, the image is absent
        after pulling, or a tag-only ref's content id no longer matches its record.
    """
    if is_digest_pinned(ref) and puller.identity(ref) is not None:
        # fast path: digest-pinned image is already present locally
        # The digest/manifest hash to local hash association is created by a pull that
        # verified the manifest's hash, so a present 'inspect' means the content was
        # trusted at pull time and the local store still has it.
        logger.info("remote image %s verified locally; reusing without pull", ref)
        return ref

    error = puller.pull(ref)
    if error is not None:
        return error
    identity = puller.identity(ref)
    if identity is None:
        return Failure(reason=f"{ref} is not present after pull")

    if is_digest_pinned(ref):
        return ref

    recorded = cache.recorded(ref)
    if recorded is None:
        cache.record(ref, identity)
        logger.info("pinned remote image %s to %s on first use", ref, identity)
        return ref
    if recorded == identity:
        logger.info("remote image %s verified against its recorded id; reusing", ref)
        return ref
    return Failure(
        reason=(
            f"remote image {ref} has changed since first use (recorded {recorded}, "
            f"now {identity}): the tag has moved. Pin a specific image by digest "
            f"(name@sha256:...) to accept it, or remove {ref} from the image cache."
        )
    )

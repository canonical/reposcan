# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Ensure a verified image is built and/or pulled."""

import logging

from reposcan.image import cache, docker
from reposcan.image.docker import DockerImageBuilder
from reposcan.image.lxd import LxdImageBuilder
from reposcan.image.spec import BuildSpec
from reposcan.result import Err, Result, is_err

logger = logging.getLogger(__name__)

# The concrete builders. They share no code, only a shape: name an image for a spec,
# read the content hash of the one present, and build. Two implementations, each the
# only builder its backend can use, so a Protocol over them bought nothing.
ImageBuilder = DockerImageBuilder | LxdImageBuilder


def is_digest_pinned(ref: str) -> bool:
    """Report whether `ref` is digest-pinned (name@sha256:...).

    The docker client verifies such a ref on pull, so it needs no trust-on-first-use
    record of its own.
    """
    return "@sha256:" in ref


def ensure_built(
    builder: ImageBuilder, spec: BuildSpec, *, force: bool = False
) -> Result[str]:
    """Build a verified image from `spec`.

    An image already present is reused IFF its hash matches its recorded identity.

    Args:
        builder: The backend builder that names, hashes, and builds the image.
        spec: The build spec that content-addresses the image.
        force: Rebuild even when a matching image is already present.

    Returns:
        The verified image reference, or an error if the build failed or the image
        vanished after building.
    """
    reference = builder.derive_reference(spec)
    if not force:
        present = builder.read_identity(reference)
        if present is not None and present == cache.find_recorded_identity(reference):
            logger.info("%s image %s verified; reusing", builder.name, reference)
            return reference
        if present is not None:
            logger.info(
                "%s image %s does not match its recorded identity; rebuilding",
                builder.name,
                reference,
            )
    logger.info("building %s image %s ...", builder.name, reference)
    if is_err(err := builder.build(spec)):
        return err
    identity = builder.read_identity(reference)
    if identity is None:
        return Err(f"{builder.name} image {reference} vanished after build")
    cache.record(reference, identity)
    return reference


def ensure_pulled(ref: str) -> Result[str]:
    """Pull `ref` and return its reference.

    If the `ref` is digest-hash-pinned (e.g., ghcr.io/org/name@sha256:...), we
    check for and re-use the image if already pulled. Notably, the digest-hash is NOT
    the same hash we see locally with `docker image inspect`; this hash is the "config
    hash", which transitively includes hashes of each container filesystem layer.
    The mapping of digest-hash to config-hash is created by docker when pulling the
    image.

    A tag-only ref is pinned on first use and -- on later pulls -- refused if its
    content id no longer matches what was first recorded. It is always pulled over the
    network to ensure we catch changes (i.e., a new :latest tag).

    Returns:
        The reference to run, or an error if the pull failed, the image is absent
        after pulling, or a tag-only ref's content id no longer matches its record.
    """
    if is_digest_pinned(ref) and docker.read_image_identity(ref) is not None:
        # fast path: digest-pinned image is already present locally
        # The digest/manifest hash to local-hash association is created by a pull that
        # verified the manifest's hash, so a present 'inspect' means the content was
        # trusted at pull time and the local store still has it.
        logger.info("remote image %s verified locally; reusing without pull", ref)
        return ref

    if is_err(err := docker.pull(ref)):
        return err
    identity = docker.read_image_identity(ref)
    if identity is None:
        return Err(f"{ref} is not present after pull")

    if is_digest_pinned(ref):
        return ref

    recorded = cache.find_recorded_identity(ref)
    if recorded is None:
        cache.record(ref, identity)
        logger.info("pinned remote image %s to %s on first use", ref, identity)
        return ref
    if recorded == identity:
        logger.info("remote image %s verified against its recorded id; reusing", ref)
        return ref
    return Err(
        f"remote image {ref} has changed since first use (recorded "
        f"{recorded}, now {identity}): the tag has moved. Pin a specific "
        f"image by digest (name@sha256:...) to accept it, or remove {ref} "
        f"from the image cache."
    )

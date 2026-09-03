# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Execution/build backends: docker, lxd, local."""

import logging
from collections.abc import Callable, Generator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass

from reposcan.execution.context import (
    RESOLUTION_WORKDIR,
    ExecutionContext,
    RunUser,
    mounted_target,
)
from reposcan.execution.docker import DockerContext
from reposcan.execution.local import LocalContext
from reposcan.execution.lxd import LxdContext
from reposcan.execution.process import Failure, run_process
from reposcan.image.docker import DockerImageBuilder
from reposcan.image.ensure import ImageBuilder, ensure_built, ensure_pulled
from reposcan.image.lxd import LxdImageBuilder
from reposcan.image.spec import (
    BASE_IMAGE,
    CANONICAL_REF,
    CANONICAL_SHORTHAND,
    INSTALL_ROOT,
    LOCAL_BUILD_SHORTHAND,
    build_spec,
)
from reposcan.paths import resolution_workdir, tools_root
from reposcan.tools.install import current_platform

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Availability:
    """Whether a backend is usable on this host, with a reason to show the user."""

    ok: bool
    reason: str = ""


@dataclass(frozen=True)
class Backend:
    """A backend for reposcan command execution."""

    name: str
    tool_root: str
    resolution_workdir: str
    probe: tuple[str, ...] = ()  # liveness command; empty means always usable
    containerized: bool = False
    context: Callable[..., ExecutionContext] | None = None  # None runs on the host
    builder: ImageBuilder | None = None
    puller: Callable[[str], str | Failure] | None = None  # None cannot pull

    def availability(self) -> Availability:
        """Report whether this backend is usable on this host."""
        if not self.probe:
            return Availability(ok=True, reason="runs on the host")
        result = run_process(list(self.probe), timeout=10)
        if isinstance(result, Failure):
            return Availability(ok=False, reason=result.reason)
        if result.exit_code != 0:
            reason = result.stderr.strip() or f"{self.probe[0]} is not available"
            return Availability(ok=False, reason=reason)
        return Availability(ok=True)

    def build_image(self, *, force: bool = False) -> str | Failure:
        """Build this backend's reposcan image, returning its verified reference."""
        if self.builder is None:
            return Failure(reason=f"the {self.name} backend cannot build images")
        return ensure_built(self.builder, build_spec(current_platform()), force=force)


# Keyed by name, in selection-precedence order: docker, then lxd, then local.
BACKENDS = {
    "docker": Backend(
        name="docker",
        tool_root=INSTALL_ROOT,
        resolution_workdir=RESOLUTION_WORKDIR,
        probe=("docker", "info"),
        containerized=True,
        context=DockerContext,
        builder=DockerImageBuilder(),
        puller=ensure_pulled,
    ),
    "lxd": Backend(
        name="lxd",
        tool_root=INSTALL_ROOT,
        resolution_workdir=RESOLUTION_WORKDIR,
        probe=("lxc", "info"),
        containerized=True,
        context=LxdContext,
        builder=LxdImageBuilder(),
        # No puller: LXD consumes OCI images differently, so it builds instead.
    ),
    "local": Backend(
        name="local",
        tool_root=str(tools_root()),
        resolution_workdir=str(resolution_workdir()),
    ),
}

# meta-name that means "pick the first available"
AUTO = "auto"


def select_backend(requested: str | None) -> Backend | Failure:
    """Choose a backend.

    Args:
        requested: The resolved backend name, or None for 'auto'. (Env and config
            fallback happens during parameter resolution, upstream of here.)

    Returns:
        The selected backend; 'auto' picks the first available of docker, lxd,
        then local. A Failure if the requested backend is unknown or
        unavailable, or if none is available.
    """
    name = requested or AUTO
    if name != AUTO and name not in BACKENDS:
        return Failure(reason=f"unknown backend {name}")

    for candidate in BACKENDS.values() if name == AUTO else [BACKENDS[name]]:
        availability = candidate.availability()
        if availability.ok:
            return candidate
        if name != AUTO:
            return Failure(
                f"selected backend ({name}) not available: {availability.reason}"
            )
    return Failure(reason="no execution backend is available")


def _reposcan_image_for(backend: Backend, image: str | None) -> str | Failure:
    """Build or pull `backend`'s reposcan image, returning the reference to run."""
    puller = backend.puller
    if puller is None or image == LOCAL_BUILD_SHORTHAND:
        if image and image != LOCAL_BUILD_SHORTHAND and puller is None:
            logger.warning(
                "the %s backend cannot pull the configured image %r; building the "
                "reposcan image locally",
                backend.name,
                image,
            )
        return backend.build_image()
    # Unset and the `canonical` shorthand both mean the pinned published image.
    ref = CANONICAL_REF if not image or image == CANONICAL_SHORTHAND else image
    reference = puller(ref)
    if isinstance(reference, Failure) and image is None:
        return Failure(
            reason=(
                f"could not pull the image {ref}: {reference.reason}. "
                f"Pass --image build to build the reposcan image locally."
            )
        )
    return reference


@dataclass(frozen=True)
class Session:
    """A running execution context and corresponding filesystem paths.

    A session that is not `ok` failed to start and carries only its exit code, so
    `context` must not be read. The context is stopped when the `start_session`
    block exits.
    """

    _context: ExecutionContext | None
    tool_root: str
    exit_code: int
    target: str | None = None  # where the scanned source is reachable in the context
    resolution_workdir: str = ""  # where dependency resolution copies the repo

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    @property
    def context(self) -> ExecutionContext:
        assert self._context is not None  # valid only when ok
        return self._context


def ensure_image(requested_backend: str | None, image: str | None) -> Failure | None:
    """Build or pull the reposcan image once, before many sessions ask for it.

    Each session still resolves `image` itself and finds the result already present.
    Doing it once here first is what keeps concurrent sessions from each starting the
    same build, or racing on the image cache, which is read and rewritten unlocked.

    Deliberately does not return the reference: handing a resolved reference back to a
    caller that passes it as `image` would route a locally built tag to the pull path.

    Returns:
        None when the image is ready, or when the backend runs no image; else the
        Failure that prevented it.
    """
    backend = select_backend(requested_backend)
    if isinstance(backend, Failure):
        return backend
    if not backend.containerized:
        return None
    resolved = _reposcan_image_for(backend, image)
    return resolved if isinstance(resolved, Failure) else None


@contextmanager
def start_session(
    requested_backend: str | None,
    *,
    mount_source: str | None = None,
    image: str | None = None,
    user: RunUser | None = None,
    env: Mapping[str, str] | None = None,
) -> Generator[Session]:
    """Select a backend and start a context in it.

    Yields a session and stops it on exit. A failed step yields a not-`ok`
    Session carrying the exit code: 2 when no backend could be selected, 1 when
    the context could not be built or started.

    Args:
        requested_backend: The backend to select, or None for 'auto'.
        mount_source: A host directory to make available for scanning, or None. The
            session's `target` reports where it is reachable in the context.
        image: The reposcan image to run: an OCI reference, `canonical` (the published
            image, used by default when unset), or `build` (build locally). Ignored by
            the local backend beyond `build`.
        user: The identity in-container processes run as by default (container backends
            only); None runs as root. A backend that shifts uids (LXD) maps it before
            the rootfs is shifted. Ignored by the local backend, which runs as the
            invoking user.
        env: Variables to add to every command.
    """
    backend = select_backend(requested_backend)
    if isinstance(backend, Failure):
        logger.error(backend.reason)
        yield Session(None, "", 2)
        return
    if backend.context is not None:
        reference = _reposcan_image_for(backend, image)
        if isinstance(reference, Failure):
            logger.error(reference.reason)
            yield Session(None, "", 1)
            return
        ctx = backend.context(
            reference or BASE_IMAGE, mount_source=mount_source, user=user, env=env
        )
        # A container mounts the source under MOUNT_PARENT.
        target = mounted_target(mount_source) if mount_source is not None else None
    else:
        # Local runs on the host: no image, no identity, no mount -- the source path
        # is the target, used directly as a cwd.
        if image and image != LOCAL_BUILD_SHORTHAND:
            logger.warning(
                "the %s backend runs on the host and cannot pull the configured "
                "image %r; it is ignored",
                backend.name,
                image,
            )
        ctx = LocalContext(f"{backend.tool_root}/bin", env)
        target = mount_source
    error = ctx.start()
    if error is not None:
        logger.error(error.reason)
        yield Session(None, "", 1)
        return
    try:
        yield Session(ctx, backend.tool_root, 0, target, backend.resolution_workdir)
    finally:
        ctx.stop()

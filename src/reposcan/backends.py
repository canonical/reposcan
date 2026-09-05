# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Execution/build backends: docker, lxd, local."""

import logging
from collections.abc import Callable, Generator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass

from reposcan import paths
from reposcan.execution.context import (
    RESOLUTION_WORKDIR,
    ExecutionContext,
    RunUser,
    locate_mounted_target,
)
from reposcan.execution.docker import DockerContext
from reposcan.execution.local import LocalContext
from reposcan.execution.lxd import LxdContext
from reposcan.execution.process import run_process
from reposcan.image.docker import DockerImageBuilder
from reposcan.image.ensure import ImageBuilder, ensure_built, ensure_pulled
from reposcan.image.lxd import LxdImageBuilder
from reposcan.image.spec import (
    BASE_IMAGE,
    CANONICAL_REF,
    CANONICAL_SHORTHAND,
    INSTALL_DIR,
    LOCAL_BUILD_SHORTHAND,
    build_spec,
)
from reposcan.result import Err, Result, get_err, is_err
from reposcan.tools.install import detect_platform

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Backend:
    """A backend for reposcan command execution."""

    name: str
    install_dir: str
    resolution_workdir: str
    probe: tuple[str, ...] = ()  # liveness command; empty means always usable
    containerized: bool = False
    context: Callable[..., ExecutionContext] | None = None  # None runs on the host
    builder: ImageBuilder | None = None
    puller: Callable[[str], Result[str]] | None = None  # None cannot pull

    def check_availability(self) -> Result[None]:
        """Check this backend is usable on this host."""
        if not self.probe:
            return None  # runs on the host
        if is_err(err := run_process(list(self.probe), timeout=10, check=True)):
            return err
        return None

    def build_image(self, *, force: bool = False) -> Result[str]:
        """Build this backend's reposcan image."""
        if self.builder is None:
            return Err(f"the {self.name} backend cannot build images")
        return ensure_built(self.builder, build_spec(detect_platform()), force=force)


# Keyed by name, in selection-precedence order: docker, then lxd, then local.
BACKENDS = {
    "docker": Backend(
        name="docker",
        install_dir=INSTALL_DIR,
        resolution_workdir=RESOLUTION_WORKDIR,
        probe=("docker", "info"),
        containerized=True,
        context=DockerContext,
        builder=DockerImageBuilder(),
        puller=ensure_pulled,
    ),
    "lxd": Backend(
        name="lxd",
        install_dir=INSTALL_DIR,
        resolution_workdir=RESOLUTION_WORKDIR,
        probe=("lxc", "info"),
        containerized=True,
        context=LxdContext,
        builder=LxdImageBuilder(),
        # No puller: LXD consumes OCI images differently, so it builds instead.
    ),
    "local": Backend(
        name="local",
        install_dir=str(paths.TOOL_INSTALL_DIR),
        resolution_workdir=str(paths.LOCAL_RESOLUTION_WORKDIR),
    ),
}

# meta-name that means "pick the first available"
AUTO = "auto"


def select_backend(requested: str | None) -> Result[Backend]:
    """Choose a backend.

    Args:
        requested: The resolved backend name, or None for 'auto'. (Env and config
            fallback happens during parameter resolution, upstream of here.)

    Returns:
        The selected backend; 'auto' picks the first available of docker, lxd,
        then local. An error if the requested backend is unknown or
        unavailable, or if none is available.
    """
    name = requested or AUTO
    if name != AUTO and name not in BACKENDS:
        return Err(f"unknown backend {name}")

    for candidate in BACKENDS.values() if name == AUTO else [BACKENDS[name]]:
        if not is_err(err := candidate.check_availability()):
            return candidate
        if name != AUTO:
            return Err(f"selected backend ({name}) not available: {err.msg}")
    return Err("no execution backend is available")


def _provision_image(backend: Backend, image: str | None) -> Result[str]:
    """Build or pull `backend`'s reposcan image."""
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
    pulled = puller(ref)
    if isinstance(pulled, Err) and image is None:
        return Err(
            f"could not pull the image {ref}: {pulled.msg}. "
            f"Pass --image build to build the reposcan image locally."
        )
    return pulled


@dataclass(frozen=True)
class Session:
    """A running execution context and corresponding filesystem paths.

    A session that is not `ok` failed to start and carries only its exit code, so
    `context` must not be read. The context is stopped when the `start_session`
    block exits.
    """

    _context: ExecutionContext | None
    install_dir: str
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


def ensure_image(requested_backend: str | None, image: str | None) -> Result[None]:
    """Build or pull the reposcan image once, before many sessions ask for it.

    Each session still resolves `image` itself and finds the result already present.
    Doing it once here first is what keeps concurrent sessions from each starting the
    same build, or racing on the image cache, which is read and rewritten unlocked.

    Deliberately does not return the reference: handing a resolved reference back to a
    caller that passes it as `image` would route a locally built tag to the pull path.

    Returns:
        None when the image is ready, or when the backend runs no image; else the
        error that prevented it.
    """
    backend = select_backend(requested_backend)
    if isinstance(backend, Err):
        return backend
    if not backend.containerized:
        return None
    return get_err(_provision_image(backend, image))


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
    if isinstance(backend, Err):
        logger.error(backend.msg)
        yield Session(None, "", 2)
        return
    if backend.context is not None:
        provisioned = _provision_image(backend, image)
        if isinstance(provisioned, Err):
            logger.error(provisioned.msg)
            yield Session(None, "", 1)
            return
        ctx = backend.context(
            provisioned or BASE_IMAGE,
            mount_source=mount_source,
            user=user,
            env=env,
        )
        # A container mounts the source under MOUNT_PARENT.
        target = (
            locate_mounted_target(mount_source) if mount_source is not None else None
        )
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
        ctx = LocalContext(f"{backend.install_dir}/bin", env)
        target = mount_source
    if is_err(err := ctx.start()):
        logger.error(err.msg)
        yield Session(None, "", 1)
        return
    try:
        yield Session(ctx, backend.install_dir, 0, target, backend.resolution_workdir)
    finally:
        ctx.stop()

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Execution/build backends: docker, lxd, local."""

import logging
from collections.abc import Generator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from reposcan.execution.context import (
    RESOLVED_PARENT,
    ExecutionContext,
    RunUser,
    mounted_target,
)
from reposcan.execution.docker import DockerContext
from reposcan.execution.local import LocalContext
from reposcan.execution.lxd import LxdContext
from reposcan.execution.process import Failure, run_process
from reposcan.image.build_spec import BASE_IMAGE, INSTALL_ROOT, build_spec
from reposcan.image.builder import ImageBuilder, ensure_built
from reposcan.image.docker import DockerImageBuilder
from reposcan.image.lxd import LxdImageBuilder
from reposcan.image.remote import (
    CANONICAL_REF,
    LOCAL_BUILD_SHORTHAND,
    DockerRemote,
    ImagePuller,
    ensure_pulled,
    resolve_remote_ref,
)
from reposcan.paths import resolve_cache, tools_root
from reposcan.tools.install import current_platform

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Availability:
    """Whether a backend is usable on this host, with a reason to show the user."""

    ok: bool
    reason: str = ""


def _probe(command: list[str]) -> Availability:
    """Report availability from a quick liveness command such as `docker info`.

    The command is ok on exit 0, otherwise not, carrying the reason.
    """
    result = run_process(command, timeout=10)
    if isinstance(result, Failure):
        return Availability(ok=False, reason=result.reason)
    if result.exit_code != 0:
        return Availability(
            ok=False, reason=result.stderr.strip() or f"{command[0]} is not available"
        )
    return Availability(ok=True)


class Backend(Protocol):
    """A place reposcan can work, reporting availability and tool/resolve paths.

    The universal surface -- the methods that mean the same thing for every backend:
    its name, whether it is usable here, where its tools live, and where dependency
    resolution copies a repo. Container-specific concerns (running in an image,
    building/pulling one) live on `ContainerBackend`.
    """

    name: str

    def availability(self) -> Availability:
        """Whether this backend is usable on this host, with a reason to show."""
        ...

    def tool_root(self) -> str:
        """Where tools live for this backend.

        The host tools dir for local, the image install root for a container.
        """
        ...

    def get_resolved_parent(self) -> str:
        """Locate the directory reposcan uses for dependency resolution copies.

        A user-writable cache dir for local, the in-image RESOLVED_PARENT for a
        container. Parallels `tool_root`: a host path locally, an image path in a
        container.
        """
        ...


@runtime_checkable
class ContainerBackend(Backend, Protocol):
    """A backend that runs in a built or pulled image.

    Adds the container surface to `Backend`: producing a context (optionally from
    an image, with a source mounted and an identity pinned), and building/pulling
    an image. `image_builder` is non-Optional (every container backend can build);
    `image_puller` is Optional.
    """

    def context(
        self,
        image: str | None = None,
        *,
        mount_source: str | None = None,
        user: RunUser | None = None,
        env: Mapping[str, str] | None = None,
    ) -> ExecutionContext:
        """Build an ExecutionContext.

        Args:
            image: The image to run, or None for the backend's default base.
            mount_source: A host directory to make available for scanning, or None.
            user: The identity in-container processes run as by default; None runs
                as root.
            env: Variables to add to every command.

        Returns:
            An unstarted execution context.
        """
        ...

    def image_builder(self) -> ImageBuilder:
        """Return an ImageBuilder for this backend."""
        ...

    def image_puller(self) -> ImagePuller | None:
        """Return an ImagePuller for this backend.

        None for a backend that cannot pull (LXD for now), which then builds locally.
        """
        ...


class LxdBackend:
    name = "lxd"

    def availability(self) -> Availability:
        return _probe(["lxc", "info"])

    def context(
        self,
        image: str | None = None,
        *,
        mount_source: str | None = None,
        user: RunUser | None = None,
        env: Mapping[str, str] | None = None,
    ) -> ExecutionContext:
        return LxdContext(
            image or BASE_IMAGE,
            mount_source=mount_source,
            user=user,
            env=env,
        )

    def image_builder(self) -> ImageBuilder:
        return LxdImageBuilder()

    def image_puller(self) -> None:
        return None  # LXD consumes OCI images differently; not supported yet

    def tool_root(self) -> str:
        return INSTALL_ROOT

    def get_resolved_parent(self) -> str:
        return RESOLVED_PARENT


class DockerBackend:
    name = "docker"

    def availability(self) -> Availability:
        return _probe(["docker", "info"])

    def context(
        self,
        image: str | None = None,
        *,
        mount_source: str | None = None,
        user: RunUser | None = None,
        env: Mapping[str, str] | None = None,
    ) -> ExecutionContext:
        return DockerContext(
            image or BASE_IMAGE,
            mount_source=mount_source,
            user=user,
            env=env,
        )

    def image_builder(self) -> ImageBuilder:
        return DockerImageBuilder()

    def image_puller(self) -> ImagePuller:
        return DockerRemote()

    def tool_root(self) -> str:
        return INSTALL_ROOT

    def get_resolved_parent(self) -> str:
        return RESOLVED_PARENT


class LocalBackend:
    """Runs on the host.

    Carries no identity (it runs as the invoking user and cannot drop privileges) and
    mounts nothing (the source path is the scan target, used directly as a cwd).
    """

    name = "local"

    def availability(self) -> Availability:
        return Availability(ok=True, reason="runs on the host")

    def tool_root(self) -> str:
        return str(tools_root())

    def get_resolved_parent(self) -> str:
        # A user-writable cache dir: the host has no root-provisioned scratch dir,
        # and resolution must not mutate the user's actual repo.
        return str(resolve_cache())


# Backends in selection-precedence order: docker, then lxd, then local.
_BACKENDS: tuple[Backend, ...] = (DockerBackend(), LxdBackend(), LocalBackend())
_BY_NAME = {backend.name: backend for backend in _BACKENDS}

# Values accepted for --backend and the `backend` config key.
BACKEND_NAMES = ("auto", *_BY_NAME)


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
    backend = requested or "auto"

    if backend != "auto" and backend not in _BY_NAME:
        return Failure(reason=f"unknown backend {backend}")

    for candidate in _BACKENDS:
        if backend not in (candidate.name, "auto"):
            continue
        availability = candidate.availability()
        if availability.ok:
            return candidate
        if backend == candidate.name:
            return Failure(
                f"selected backend ({candidate.name}) not available: "
                f"{availability.reason}"
            )
    return Failure(reason="no execution backend is available")


def _tool_image_for(
    backend: ContainerBackend, image: str | None, *, tool_image: bool
) -> str | None | Failure:
    """Build or pull `backend`'s tool image, returning the reference to run.

    None means run the backend's plain base image. `tool_image=False` asks for that,
    but only where the image would have been built: a configured pull is honoured
    either way, so the bootstrap path still gets the image it named.
    """
    puller = backend.image_puller()
    if puller is None or image == LOCAL_BUILD_SHORTHAND:
        if not tool_image:
            return None
        if image and image != LOCAL_BUILD_SHORTHAND and puller is None:
            logger.warning(
                "the %s backend cannot pull the configured image %r; building the "
                "tool image locally",
                backend.name,
                image,
            )
        return ensure_built(backend.image_builder(), build_spec(current_platform()))
    ref = resolve_remote_ref(image) if image else CANONICAL_REF
    reference = ensure_pulled(puller, ref)
    if isinstance(reference, Failure) and image is None:
        return Failure(
            reason=(
                f"could not pull the image {ref}: {reference.reason}. "
                f"Pass --image build to build the tool image locally."
            )
        )
    return reference


@dataclass(frozen=True)
class Session:
    """A started place to run a command in.

    It carries its context and where its tools live, or -- when not `ok` -- a
    failure exit code. `context` is valid only when `ok`; it is stopped when the
    `start_session` block exits.
    """

    _context: ExecutionContext | None
    tool_root: str
    exit_code: int
    target: str | None = None  # where the scanned source is reachable in the context
    resolved_parent: str = ""  # where dependency resolution copies the repo

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    @property
    def context(self) -> ExecutionContext:
        assert self._context is not None  # valid only when ok
        return self._context


def ensure_image(requested_backend: str | None, image: str | None) -> Failure | None:
    """Build or pull the tool image once, before many sessions ask for it.

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
    if not isinstance(backend, ContainerBackend):
        return None
    resolved = _tool_image_for(backend, image, tool_image=True)
    return resolved if isinstance(resolved, Failure) else None


@contextmanager
def start_session(
    requested_backend: str | None,
    *,
    tool_image: bool,
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
        tool_image: Use the verified tool image (built on demand) when True,
            else a plain container.
        mount_source: A host directory to make available for scanning, or None. The
            session's `target` reports where it is reachable in the context.
        image: The tool image to run: an OCI reference, `canonical` (the published
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
    if isinstance(backend, ContainerBackend):
        reference = _tool_image_for(backend, image, tool_image=tool_image)
        if isinstance(reference, Failure):
            logger.error(reference.reason)
            yield Session(None, "", 1)
            return
        ctx = backend.context(reference, mount_source=mount_source, user=user, env=env)
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
        ctx = LocalContext(f"{backend.tool_root()}/bin", env)
        target = mount_source
    error = ctx.start()
    if error is not None:
        logger.error(error.reason)
        yield Session(None, "", 1)
        return
    try:
        yield Session(
            ctx, backend.tool_root(), 0, target, backend.get_resolved_parent()
        )
    finally:
        ctx.stop()

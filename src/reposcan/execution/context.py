# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Value types and the ExecutionContext Protocol."""

import logging
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from reposcan.execution.process import ExecResult
from reposcan.result import Result, get_err, get_value

logger = logging.getLogger(__name__)

# Parent directory a scanned source is bind-mounted under inside a container. A fixed
# parent (rather than the filesystem root) avoids colliding with system directories.
MOUNT_PARENT = "/scan"

# Parent directory that dependency resolution copies a repo into (as "<parent>/<repo
# name>", preserving the name so scan-output locations read naturally). The copy is
# writable, unlike the read-only mount. Set up in the image: owned by the scan user
# and trusted by git.
RESOLUTION_WORKDIR = "/resolved-deps"

# default unprivileged user for in-container processes. Kept as the image's
# fallback user (created at build time) and as the model-layer default identity;
# the CLI overrides it with the invoking host user (see get_host_user).
SCAN_USER = "reposcan"
SCAN_UID = 10000
SCAN_GID = 10000
SCAN_HOME = "/home/reposcan"

# Maximum supplementary groups mapped into a container. LXD's raw.idmap parser has a
# practical line limit and most file access is gated on the primary gid or world-
# readable files, so a cap keeps the idmap small without losing the common case.
_MAX_GROUPS = 32


@dataclass(frozen=True)
class RunUser:
    """The identity in-container processes run as.

    Carries the uid, primary gid, and supplementary gids. The gids are raw numbers
    (setpriv --groups and LXD raw.idmap both take numeric gids), so no /etc/passwd or
    /etc/group entry is needed for the user.
    """

    uid: int
    gid: int
    groups: tuple[int, ...]


def get_host_user() -> RunUser:
    """Return the invoking host user as a RunUser.

    Uses the real uid/gid and supplementary groups (capped at _MAX_GROUPS, with a
    warning and truncation when the host user is in more). Root gets no supplementary
    groups (root bypasses group checks, and its groups are not worth mapping).
    """
    uid = os.getuid()
    gid = os.getgid()
    if uid == 0:
        return RunUser(0, 0, ())
    groups = sorted(set(os.getgroups()) | {gid})
    if len(groups) > _MAX_GROUPS:
        logger.warning(
            "host user is in %d groups; capping supplementary groups at %d",
            len(groups),
            _MAX_GROUPS,
        )
        groups = groups[:_MAX_GROUPS]
    return RunUser(uid, gid, tuple(groups))


def wrap_with_setpriv(command: Sequence[str], user: RunUser) -> list[str]:
    """Wrap `command` with setpriv so it runs as `user`.

    Drops the (root) caller to the user's uid and primary gid and sets its
    supplementary groups by raw gid (setpriv --groups takes numeric gids, so no
    /etc/group entry is needed). With no supplementary groups, --clear-groups drops
    the caller's groups entirely -- setpriv keeps them by default, which would leak
    root's groups to the dropped user. setpriv leaves the environment and working
    directory untouched, so the command still sees the env and cwd it was given.
    """
    argv = ["setpriv", f"--reuid={user.uid}", f"--regid={user.gid}"]
    if user.groups:
        argv.append(f"--groups={','.join(str(g) for g in user.groups)}")
    else:
        argv.append("--clear-groups")
    argv.append("--")
    return [*argv, *command]


def select_home(uid: int) -> str:
    """Select the HOME env var for a command running as `uid`.

    The built-in scan user has a real home; any other uid gets `/tmp`, which is
    world-writable so tools can still write their caches.
    """
    homes = {SCAN_UID: SCAN_HOME, 0: "/root"}
    return homes.get(uid) or "/tmp"


def resolve_env(specs: Sequence[str]) -> dict[str, str]:
    """Resolve `NAME[=VALUE]` specs to variables."""
    resolved: dict[str, str] = {}
    for spec in specs:
        name, sep, value = spec.partition("=")
        if sep:
            resolved[name] = value
        elif name in os.environ:
            resolved[name] = os.environ[name]
        else:
            logger.warning("--env %s: not set in the environment, skipping", name)
    return resolved


def locate_mounted_target(mount_source: str) -> str:
    """Where a mounted source directory appears inside a container.

    The source keeps its own directory name under `MOUNT_PARENT`, so tools that
    surface the directory in their output show the real repository name.

    Args:
        mount_source: The host directory being mounted for scanning.

    Returns:
        The in-container path, e.g. `/scan/<basename>`.
    """
    return f"{MOUNT_PARENT}/{os.path.basename(os.path.realpath(mount_source))}"


def find_linked_git_dirs(mount_source: str) -> list[str]:
    """Find the git directories a linked worktree depends on but does not contain.

    A linked worktree (`git worktree add`, which `gh clone-repos` uses) has a `.git`
    file rather than a directory: `gitdir: <path>` names its private git dir, whose
    `commondir` names the repository's shared git dir (a main `.git`, or a bare
    mirror). Neither lies under the worktree, so a container that mounts only the
    worktree sees a dangling pointer, and git (and trufflehog's history mode) treat the
    target as a plain directory.

    A container mounts each returned directory at its own host path, so the absolute
    pointer in `.git` resolves unchanged inside it.

    Args:
        mount_source: The host directory being mounted for scanning.

    Returns:
        The directories to mount at their own path: the shared git dir, plus the
        worktree's private git dir when it lies outside the shared one. Empty when
        `mount_source` is not a linked worktree, or its pointer cannot be followed.
    """
    pointer = os.path.join(mount_source, ".git")
    if not os.path.isfile(pointer):
        return []  # a regular checkout (or not a repository): nothing outside it
    try:
        with open(pointer, encoding="utf-8") as handle:
            first_line = handle.readline().strip()
    except OSError as exc:
        logger.warning("could not read %s: %s", pointer, exc)
        return []
    if not first_line.startswith("gitdir:"):
        return []
    private = os.path.normpath(first_line.removeprefix("gitdir:").strip())
    if not os.path.isabs(private):
        # A relative pointer (worktree.useRelativePaths) resolves against wherever the
        # worktree is mounted, not its host path, so mounting at the host path cannot
        # repair it.
        logger.warning(
            "%s is a worktree with a relative gitdir pointer; its git history will "
            "not be visible inside the scan container",
            mount_source,
        )
        return []
    shared = private  # with no `commondir`, the private dir is the whole repository
    try:
        with open(os.path.join(private, "commondir"), encoding="utf-8") as handle:
            shared = os.path.normpath(os.path.join(private, handle.read().strip()))
    except OSError:
        pass
    if not os.path.isdir(shared):
        logger.warning("%s points at missing git dir %s", mount_source, shared)
        return []
    if private == shared or private.startswith(shared + os.sep):
        return [shared]
    return [shared, private]


class ExecutionContext(Protocol):
    """A place reposcan can run commands: the local host, or an ephemeral container.

    Whether the backend is available is decided before a context is made (see
    backends.py), so a context is just a lifecycle: start(), run(), stop().
    """

    name: str

    def start(self) -> Result[None]:
        """Start the context."""
        ...

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        user: RunUser | None = None,
        timeout: float | None = None,
        check: bool = False,
        stream_stdout: bool = False,
        stream_stderr: bool = False,
        stdin: str | None = None,
    ) -> Result[ExecResult]:
        """Run `command`.

        `user`, when set, runs this one command as that identity, overriding the
        context's default for this call (container backends only; the local context
        ignores it and runs as the invoking user). None runs as the context's default
        identity -- the one set at construction, or root when none was set.

        Returns:
            An ExecResult or Err.
        """
        ...

    def stop(self) -> None:
        """Stop the context.

        Safe to call whether or not start() succeeded.
        """
        ...


def read_file(
    ctx: ExecutionContext,
    path: str,
    *,
    cwd: str | None = None,
) -> str | None:
    """Read the text of `path` through `ctx` (via `cat`)."""
    run = get_value(ctx.run(["cat", path], cwd=cwd, check=True))
    return run.stdout if run is not None else run


def write_file(
    ctx: ExecutionContext,
    path: str,
    content: str,
    *,
    cwd: str | None = None,
) -> Result[None]:
    """Write `content` to `path` through `ctx` (via `cp` from stdin)."""
    argv = ["cp", "/dev/stdin", path]
    return get_err(ctx.run(argv, cwd=cwd, stdin=content, check=True))

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Value types and the ExecutionContext Protocol.

An ExecutionContext is a place reposcan can run commands: the local host, or an
ephemeral Docker/LXD container. main owns its lifecycle with start() and stop(),
and commands run() in between. Contexts are structural (Protocol) types, so a
concrete context is any object with the right methods.

Outcomes are returned, not raised. start() returns None on success or a Failure
carrying the reason. run() yields an ExecResult with the command's exit code and
captured output (whatever that exit code), or a Failure when the command could not
be started or timed out.
"""

import logging
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from reposcan.execution.process import ExecResult, Failure, succeeded

logger = logging.getLogger(__name__)

# Parent directory a scanned source is bind-mounted under inside a container. A fixed
# parent (rather than the filesystem root) avoids colliding with system directories.
MOUNT_PARENT = "/scan"

# Parent directory that dependency resolution copies a repo into (as "<parent>/<repo
# name>", preserving the name so scan-output locations read naturally). The copy is
# writable, unlike the read-only mount. Set up in the image: owned by the scan user
# and trusted by git.
RESOLVED_PARENT = "/resolved-deps"

# default unprivileged user for in-container processes. Kept as the image's
# fallback user (created at build time) and as the model-layer default identity;
# the CLI overrides it with the invoking host user (see host_user).
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


def host_user() -> RunUser:
    """The invoking host user, as a RunUser.

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


def as_user(command: Sequence[str], user: RunUser) -> list[str]:
    """`command` wrapped to run as `user` via setpriv.

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


def home_for(uid: int) -> str:
    """The HOME to give a command running as `uid` (for tool caches).

    The built-in scan user has a real home; any other uid gets `/tmp`, which is
    world-writable so tools can still write their caches.
    """
    homes = {SCAN_UID: SCAN_HOME, 0: "/root"}
    return homes.get(uid) or "/tmp"


def mounted_target(mount_source: str) -> str:
    """Where a mounted source directory appears inside a container.

    The source keeps its own directory name under `MOUNT_PARENT`, so tools that
    surface the directory in their output show the real repository name.

    Args:
        mount_source: The host directory being mounted for scanning.

    Returns:
        The in-container path, e.g. `/scan/<basename>`.
    """
    return f"{MOUNT_PARENT}/{os.path.basename(os.path.realpath(mount_source))}"


class ExecutionContext(Protocol):
    """A place reposcan can run commands: the local host, or an ephemeral container.

    Whether the backend is available is decided before a context is made (see
    backends.py), so a context is just a lifecycle: start(), run(), stop().
    """

    name: str

    def start(self) -> Failure | None: ...

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        user: RunUser | None = None,
        timeout: float | None = None,
        stream_stdout: bool = False,
        stream_stderr: bool = False,
        stdin: str | None = None,
    ) -> ExecResult | Failure:
        """Run `command`, returning its result or a Failure.

        `user`, when set, runs this one command as that identity, overriding the
        context's default for this call (container backends only; the local context
        ignores it and runs as the invoking user). None runs as the context's default
        identity -- the one set at construction, or root when none was set.
        """
        ...

    def stop(self) -> None: ...


def read_file(
    ctx: ExecutionContext,
    path: str,
    *,
    cwd: str | None = None,
) -> str | None:
    """The text content of `path` read through `ctx` (via `cat`), or None on failure."""
    result = ctx.run(["cat", path], cwd=cwd)
    return result.stdout if succeeded(result) else None


def write_file(
    ctx: ExecutionContext,
    path: str,
    content: str,
    *,
    cwd: str | None = None,
) -> bool:
    """Write `content` to `path` through `ctx`, returning whether it succeeded."""
    result = ctx.run(["cp", "/dev/stdin", path], cwd=cwd, stdin=content)
    return succeeded(result)

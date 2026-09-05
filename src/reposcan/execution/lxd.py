# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""LXD execution context: run commands in an ephemeral container."""

from collections.abc import Mapping, Sequence
from uuid import uuid4

from reposcan.execution.context import (
    RunUser,
    locate_mounted_target,
    select_home,
    wrap_with_setpriv,
)
from reposcan.execution.firewall import warn_if_lxd_bridge_blocked
from reposcan.execution.process import ExecResult, run_process
from reposcan.result import Err, Result, get_err, is_err

# The dedicated LXD project reposcan works in. Every instance- or image-acting lxc
# command is pinned to it (the LXC prefix) so reposcan's ephemeral containers and its
# built reposcan image never land in the user's default project.
PROJECT = "reposcan"
LXC = ["lxc", "--project", PROJECT]


def ensure_project() -> Result[None]:
    """Create reposcan's LXD project if it does not exist yet.

    features.images=true keeps the built reposcan image inside this project rather
    than the default one; features.profiles=false borrows the default project's
    profile so containers still get its root disk and network and launch with no
    per-project setup.

    Returns:
        None when the project exists or was created; an error if creation failed.
    """
    if not is_err(run_process(["lxc", "project", "show", PROJECT], check=True)):
        return None
    argv = [
        "lxc",
        "project",
        "create",
        PROJECT,
        "-c",
        "features.images=true",
        "-c",
        "features.profiles=false",
    ]
    return get_err(run_process(argv, check=True))


class LxdContext:
    """Runs commands in an ephemeral container via `lxc`, launched from `image`.

    `image` is a stock base for plain runs, or the reposcan image for scans.
    """

    name = "lxd"

    def __init__(
        self,
        image: str,
        mount_source: str | None = None,
        user: RunUser | None = None,
        env: Mapping[str, str] | None = None,
    ) -> None:
        self._image = image
        self._mount_source = mount_source
        self._user = user  # the default identity for every run (None = root)
        self._env = dict(env or {})
        self._instance_name: str | None = None

    def start(self) -> Result[None]:
        warn_if_lxd_bridge_blocked()
        if is_err(err := ensure_project()):
            return err
        handle = f"reposcan-{uuid4().hex[:12]}"
        argv = [*LXC, "launch", self._image, handle, "--ephemeral"]
        idmap = _build_raw_idmap(self._user)
        if idmap is not None:
            # Set at launch: LXD shifts the rootfs uids as it starts, so the idmap
            # must be in place before the instance runs. Per-instance (not a profile)
            # so each scan maps exactly the invoking user.
            argv += ["--config", f"raw.idmap={idmap}"]
        result = run_process(argv)
        if isinstance(result, Err):
            return result
        if result.exit_code != 0:
            return Err(result.stderr.strip() or "lxc launch failed")
        self._instance_name = handle
        if self._mount_source is not None:
            return self._mount(handle, self._mount_source)
        return None

    def _mount(self, handle: str, mount_source: str) -> Result[None]:
        """Attach `mount_source` read-only at `locate_mounted_target(mount_source)`.

        Args:
            handle: The running instance to attach the disk to.
            mount_source: The host directory to make available for scanning.

        Returns:
            None on success, or an error if the disk device could not be added.
        """
        argv = [
            *LXC,
            "config",
            "device",
            "add",
            handle,
            "scan",
            "disk",
            f"source={mount_source}",
            f"path={locate_mounted_target(mount_source)}",
            "readonly=true",
        ]
        return get_err(run_process(argv, check=True))

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
        if self._instance_name is None:
            return Err("container is not started")
        argv = [*LXC, "exec", self._instance_name]
        if cwd is not None:
            argv += ["--cwd", cwd]
        run_env = {**self._env, **(env or {})}
        command = list(command)
        effective = self._user if user is None else user
        if effective is not None:
            run_env.setdefault("HOME", select_home(effective.uid))
            command = wrap_with_setpriv(command, effective)
        for key, value in sorted(run_env.items()):
            argv += ["--env", f"{key}={value}"]
        argv += ["--", *command]
        return run_process(
            argv,
            timeout=timeout,
            check=check,
            stream_stdout=stream_stdout,
            stream_stderr=stream_stderr,
            stdin=stdin,
        )

    def stop(self) -> None:
        if self._instance_name is not None:
            run_process([*LXC, "stop", self._instance_name])
            self._instance_name = None


def _build_raw_idmap(user: RunUser | None) -> str | None:
    """Build an LXD raw.idmap for `user`.

    `both <uid> <uid>` maps both the uid and the primary gid to identity; each
    supplementary gid gets a `gid <gid> <gid>` line. Root (uid 0) is already in the
    default idmap, so it needs no entry -- mapping it again would conflict.

    Returns:
        The raw.idmap lines, or None when no user is set or the user is root.
    """
    if user is None or user.uid == 0:
        return None
    lines = [f"both {user.uid} {user.uid}"]
    for gid in user.groups:
        if gid != user.gid:  # `both` already mapped the primary gid
            lines.append(f"gid {gid} {gid}")
    return "\n".join(lines)

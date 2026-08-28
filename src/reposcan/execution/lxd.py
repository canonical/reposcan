# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""LXD execution context: run commands in an ephemeral container.

Uses the lxc CLI (no SDK).
"""

import os
from collections.abc import Mapping, Sequence

from reposcan.execution.context import (
    RunUser,
    as_user,
    home_for,
    mounted_target,
)
from reposcan.execution.firewall import warn_if_lxd_bridge_blocked
from reposcan.execution.process import ExecResult, Failure, run_process, succeeded

# The dedicated LXD project reposcan works in. Every instance- or image-acting lxc
# command is pinned to it (the LXC prefix) so reposcan's ephemeral containers and its
# built tool image never land in the user's default project.
PROJECT = "reposcan"
LXC = ["lxc", "--project", PROJECT]


def ensure_project() -> Failure | None:
    """Create reposcan's LXD project if it does not exist yet; a no-op once it does.

    features.images=true keeps the built tool image inside this project rather than the
    default one; features.profiles=false borrows the default project's profile so
    containers still get its root disk and network and launch with no per-project setup.

    Returns:
        None when the project already exists or was created; a Failure if creating
        it failed.
    """
    presence_check = run_process(["lxc", "project", "show", PROJECT])
    if succeeded(presence_check):
        return None
    created = run_process(
        [
            "lxc",
            "project",
            "create",
            PROJECT,
            "-c",
            "features.images=true",
            "-c",
            "features.profiles=false",
        ],
        check=True,
    )
    return created if isinstance(created, Failure) else None


class LxdContext:
    """Runs commands in an ephemeral container via `lxc`, launched from `image`.

    `image` is a stock base for plain runs, or the tool image for scans.
    """

    name = "lxd"

    def __init__(
        self, image: str, mount_source: str | None = None, user: RunUser | None = None
    ) -> None:
        self._image = image
        self._mount_source = mount_source
        self._user = user  # the default identity for every run (None = root)
        self._instance_name: str | None = None

    def start(self) -> Failure | None:
        warn_if_lxd_bridge_blocked()
        project_creation_error = ensure_project()
        if project_creation_error is not None:
            return project_creation_error
        handle = f"reposcan-{os.getpid()}"
        argv = [*LXC, "launch", self._image, handle, "--ephemeral"]
        idmap = _raw_idmap(self._user)
        if idmap is not None:
            # Set at launch: LXD shifts the rootfs uids as it starts, so the idmap
            # must be in place before the instance runs. Per-instance (not a profile)
            # so each scan maps exactly the invoking user.
            argv += ["--config", f"raw.idmap={idmap}"]
        result = run_process(argv)
        if isinstance(result, Failure):
            return result
        if result.exit_code != 0:
            return Failure(reason=result.stderr.strip() or "lxc launch failed")
        self._instance_name = handle
        if self._mount_source is not None:
            return self._mount(handle, self._mount_source)
        return None

    def _mount(self, handle: str, mount_source: str) -> Failure | None:
        """Attach `mount_source` read-only at `mounted_target(mount_source)`.

        Args:
            handle: The running instance to attach the disk to.
            mount_source: The host directory to make available for scanning.

        Returns:
            None on success, or a Failure if the disk device could not be added.
        """
        add = run_process(
            [
                *LXC,
                "config",
                "device",
                "add",
                handle,
                "scan",
                "disk",
                f"source={mount_source}",
                f"path={mounted_target(mount_source)}",
                "readonly=true",
            ],
            check=True,
        )
        return add if isinstance(add, Failure) else None

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
        if self._instance_name is None:
            return Failure(reason="container is not started")
        argv = [*LXC, "exec", self._instance_name]
        if cwd is not None:
            argv += ["--cwd", cwd]
        run_env = dict(env or {})
        command = list(command)
        effective = self._user if user is None else user
        if effective is not None:
            run_env.setdefault("HOME", home_for(effective.uid))
            command = as_user(command, effective)
        for key, value in sorted(run_env.items()):
            argv += ["--env", f"{key}={value}"]
        argv += ["--", *command]
        return run_process(
            argv,
            timeout=timeout,
            stream_stdout=stream_stdout,
            stream_stderr=stream_stderr,
            stdin=stdin,
        )

    def stop(self) -> None:
        if self._instance_name is not None:
            run_process([*LXC, "stop", self._instance_name])
            self._instance_name = None


def _raw_idmap(user: RunUser | None) -> str | None:
    """A LXD raw.idmap mapping `user` to identity, or None when no mapping is needed.

    `both <uid> <uid>` maps both the uid and the primary gid to identity; each
    supplementary gid gets a `gid <gid> <gid>` line. Root (uid 0) is already in the
    default idmap, so it needs no entry -- mapping it again would conflict. None is
    also returned when no user is set (the default idmap applies).
    """
    if user is None or user.uid == 0:
        return None
    lines = [f"both {user.uid} {user.uid}"]
    for gid in user.groups:
        if gid != user.gid:  # `both` already mapped the primary gid
            lines.append(f"gid {gid} {gid}")
    return "\n".join(lines)

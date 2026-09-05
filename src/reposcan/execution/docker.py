# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Docker execution context: run commands in an ephemeral container.

Uses the docker CLI (no SDK).
"""

from collections.abc import Mapping, Sequence

from reposcan.execution.context import (
    RunUser,
    locate_mounted_target,
    select_home,
    wrap_with_setpriv,
)
from reposcan.execution.process import ExecResult, run_process
from reposcan.result import Err, Result


class DockerContext:
    """Runs commands in an ephemeral container via `docker`, started from `image`.

    When `mount_source` is given, that host directory is bind-mounted read-only at
    `locate_mounted_target(mount_source)` so a scan can reach the repository.
    """

    name = "docker"

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
        argv = ["docker", "run", "-d", "--rm"]
        if self._mount_source is not None:
            src = self._mount_source
            argv += ["-v", f"{src}:{locate_mounted_target(src)}:ro"]
        argv += [self._image, "sleep", "infinity"]
        result = run_process(argv)
        if isinstance(result, Err):
            return result
        if result.exit_code != 0:
            return Err(result.stderr.strip() or "docker run failed")
        self._instance_name = result.stdout.strip()
        return None

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
        argv = ["docker", "exec"]
        if stdin is not None:
            argv.append("-i")  # keep stdin open so the command can read it
        if cwd is not None:
            argv += ["-w", cwd]
        run_env = {**self._env, **(env or {})}
        command = list(command)
        effective = self._user if user is None else user
        if effective is not None:
            run_env.setdefault("HOME", select_home(effective.uid))
            command = wrap_with_setpriv(command, effective)
        for key, value in sorted(run_env.items()):
            argv += ["-e", f"{key}={value}"]
        argv += [self._instance_name, *command]
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
            run_process(["docker", "rm", "-f", self._instance_name])
            self._instance_name = None

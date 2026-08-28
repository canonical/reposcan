# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Local execution context: run commands directly on the host."""

import logging
import os
from collections.abc import Mapping, Sequence

from reposcan.execution.context import RunUser
from reposcan.execution.process import ExecResult, Failure, run_process

logger = logging.getLogger(__name__)


class LocalContext:
    """Runs commands on the host.

    Nothing to start or stop. Per-command `env` is overlaid on the inherited host
    environment. The local backend always runs as the invoking user. Always prepends
    `tool_root` to PATH for command execution.
    """

    name = "local"

    def __init__(self, tool_root: str | None = None) -> None:
        self._tool_root = tool_root

    def start(self) -> Failure | None:
        return None

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
        if user is not None:
            logger.warning(
                "the local backend runs as the invoking user (uid %d); ignoring the "
                "requested identity (uid %d)",
                os.getuid(),
                user.uid,
            )
        run_env = {**os.environ, **env} if env is not None else None
        if self._tool_root is not None:
            path = f"{self._tool_root}{os.pathsep}{os.environ.get('PATH', '')}"
            if run_env is None:
                run_env = {**os.environ, "PATH": path}
            else:
                run_env["PATH"] = path
        return run_process(
            command,
            cwd=cwd,
            env=run_env,
            timeout=timeout,
            stream_stdout=stream_stdout,
            stream_stderr=stream_stderr,
            stdin=stdin,
        )

    def stop(self) -> None:
        return None

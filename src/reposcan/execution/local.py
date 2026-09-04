# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Local execution context: run commands directly on the host."""

import logging
import os
from collections.abc import Mapping, Sequence

from reposcan.execution.context import RunUser
from reposcan.execution.process import ExecResult, Failure, run_process

logger = logging.getLogger(__name__)

# Host environment variables to pass through by default.
_ALLOWED_ENV_VARS = (
    "HOME",
    "LANG",
    "LC_ALL",
    "PATH",
    # temporary and cache dirs
    "TMPDIR",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    # network connectivity
    "CURL_CA_BUNDLE",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NODE_EXTRA_CA_CERTS",
    "NO_PROXY",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    # curl reads the lowercase spellings and ignores the uppercase ones.
    "http_proxy",
    "https_proxy",
    "no_proxy",
)


class LocalContext:
    """Runs commands on the host.

    Nothing to start or stop. Runs as the invoking user. Always prepends `bin_dir`
    to PATH. Host env vars are masked by reposcan's allow-list.
    """

    name = "local"

    def __init__(
        self, bin_dir: str | None = None, env: Mapping[str, str] | None = None
    ) -> None:
        self._bin_dir = bin_dir
        self._env = dict(env or {})

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
        environment = {
            name: os.environ[name] for name in _ALLOWED_ENV_VARS if name in os.environ
        }
        environment.update(self._env)
        environment.update(env or {})
        if self._bin_dir is not None:
            # An empty trailing element would put the scanned repository on PATH
            rest = environment.get("PATH", "")
            environment["PATH"] = (
                f"{self._bin_dir}{os.pathsep}{rest}" if rest else self._bin_dir
            )
        return run_process(
            command,
            cwd=cwd,
            env=environment,
            timeout=timeout,
            stream_stdout=stream_stdout,
            stream_stderr=stream_stderr,
            stdin=stdin,
        )

    def stop(self) -> None:
        return None

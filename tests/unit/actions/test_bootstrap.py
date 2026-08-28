# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the `reposcan bootstrap` action (reposcan.actions.bootstrap).

A fake execution context records the shell commands it is handed and can be told to
fail those matching a substring, so the action's resolution, ordering, and
failure-domain behavior can be checked without installing anything.
"""

import logging
from collections.abc import Mapping, Sequence

from reposcan.actions.bootstrap import bootstrap
from reposcan.execution.process import ExecResult, Failure
from reposcan.tools.model import Platform

_LINUX = Platform("linux", "amd64")
_ROOT = "/opt/tools"


class _FakeContext:
    """Records every command and returns success, unless a command contains
    `fail_on`, in which case that one fails."""

    name = "fake"

    def __init__(self, fail_on: str | None = None) -> None:
        self.scripts: list[str] = []
        self.argvs: list[list[str]] = []
        self._fail_on = fail_on

    def start(self) -> Failure | None:
        return None

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        user: object | None = None,
        timeout: float | None = None,
        stream_stdout: bool = False,
        stream_stderr: bool = False,
        stdin: str | None = None,
    ) -> ExecResult | Failure:
        script = stdin or ""  # sh -eu, with the script fed on stdin
        self.argvs.append(list(command))
        self.scripts.append(script)
        if self._fail_on is not None and self._fail_on in script:
            return ExecResult(exit_code=1, stdout="", stderr="download failed")
        return ExecResult(exit_code=0, stdout="", stderr="")

    def stop(self) -> None:
        return None


class _ListHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


def _capture_logs():  # returns (handler, remover)
    # The action logs progress at INFO; lower the package logger to INFO for the
    # duration so those records reach our handler, then restore it.
    handler = _ListHandler()
    logger = logging.getLogger("reposcan")
    previous_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    def remove() -> None:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)

    return handler, remove


def test_unknown_tool_is_rejected() -> None:
    context = _FakeContext()
    handler, remove = _capture_logs()
    try:
        code = bootstrap(context, ["not-a-tool"], _LINUX, _ROOT)
    finally:
        remove()
    assert code == 2
    assert not context.scripts  # nothing was installed
    assert any("unknown tool" in message for message in handler.messages)


def test_installs_a_named_tool_and_pulls_in_its_prerequisite() -> None:
    context = _FakeContext()
    handler, remove = _capture_logs()
    try:
        code = bootstrap(context, ["semgrep"], _LINUX, _ROOT)
    finally:
        remove()
    assert code == 0
    installing = [m for m in handler.messages if m.startswith("installing")]
    # uv (the prerequisite) is installed before semgrep.
    assert any("installing uv" in m for m in installing)
    assert any("installing semgrep" in m for m in installing)
    uv_at = next(i for i, m in enumerate(installing) if "installing uv" in m)
    semgrep_at = next(i for i, m in enumerate(installing) if "installing semgrep" in m)
    assert uv_at < semgrep_at


def test_scripts_run_on_stdin_not_as_a_shell_argument() -> None:
    # A hash-pinned lock embedded in the command can exceed the kernel's per-argument
    # size limit, so the script must reach sh on stdin, never in argv.
    context = _FakeContext()
    code = bootstrap(context, ["checkov"], _LINUX, _ROOT)
    assert code == 0
    assert context.argvs and all(argv == ["sh", "-eu"] for argv in context.argvs)
    # the lock (with --hash pins) is present, but only via stdin
    assert any("--hash" in script for script in context.scripts)


def test_a_failing_tool_is_isolated_and_the_rest_proceed() -> None:
    # Fail trufflehog's install; semgrep (a later group) must still be attempted.
    context = _FakeContext(fail_on="trufflehog")
    handler, remove = _capture_logs()
    try:
        code = bootstrap(context, ["trufflehog", "semgrep"], _LINUX, _ROOT)
    finally:
        remove()
    assert code == 1
    assert any("failed to install trufflehog" in m for m in handler.messages)
    assert any("installing semgrep" in m for m in handler.messages)


def test_no_names_installs_every_tool() -> None:
    context = _FakeContext()
    handler, remove = _capture_logs()
    try:
        code = bootstrap(context, [], _LINUX, _ROOT)
    finally:
        remove()
    assert code == 0
    installing = [m for m in handler.messages if m.startswith("installing")]
    assert any("installing govulncheck" in m for m in installing)
    assert any("installing checkov" in m for m in installing)
    # Prerequisites are pulled in even though they are not user-facing tools.
    assert any("installing uv" in m for m in installing)
    assert any("installing go " in m for m in installing)

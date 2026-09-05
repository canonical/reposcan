# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Run a subprocess and return its outcome as a value."""

import subprocess
import sys
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import IO, TextIO

from reposcan.result import Err, Result


@dataclass(frozen=True)
class ExecResult:
    """The outcome of a command that ran to completion (any exit code)."""

    exit_code: int
    stdout: str
    stderr: str


class _Tee:
    """Drains one pipe into a buffer and optionally echoes it to a live stream.

    When a live stream is given, echoes it to that stream a character at a time
    (like `tee`), so output with no trailing newline (prompts, progress bars) shows
    immediately instead of waiting for the line to end. The capture stays
    line-oriented. One instance handles one pipe; stdout and stderr each get their own
    so that reading both concurrently (on separate threads) never deadlocks on a full
    pipe buffer. A None live stream captures without echoing.
    """

    def __init__(self, source: IO[str], live: TextIO | None) -> None:
        self._source = source
        self._live = live
        self._captured: list[str] = []

    def drain(self) -> None:
        """Read the source to EOF, echoing live and buffering as whole lines."""
        line: list[str] = []
        while True:
            char = self._source.read(1)
            if not char:  # EOF
                break
            if self._live is not None:
                self._live.write(char)
                self._live.flush()
            line.append(char)
            if char == "\n":
                self._captured.append("".join(line))
                line = []
        if line:  # trailing text with no final newline
            self._captured.append("".join(line))

    @property
    def captured(self) -> str:
        return "".join(self._captured)


def run_process(
    command: Sequence[str],
    *,
    cwd: str | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float | None = None,
    check: bool = False,
    stream_stdout: bool = False,
    stream_stderr: bool = False,
    stdin: str | None = None,
) -> Result[ExecResult]:
    """Run `command` and return its outcome.

    Both stdout and stderr are always captured into the returned ExecResult. The
    stream flags additionally echo a pipe to this process's console as it runs, for
    live progress.

    With `check`, a returned ExecResult has always exited 0 (like
    `subprocess.run(check=True)`, but returned rather than raised).

    Args:
        command: The argv to run; the first element is the executable.
        cwd: Working directory for the process, or None to inherit this process's.
        env: Environment for the process, or None to inherit this process's.
        timeout: Seconds to wait before killing the process, or None for no limit.
        check: When True, treat a nonzero exit as an Err rather than an ExecResult.
        stream_stdout: When True, echo the command's stdout live as it runs.
        stream_stderr: When True, echo the command's stderr live as it runs.
        stdin: Text to feed the command on standard input, or None to inherit this
            process's stdin. The stream is closed after the text is written.

    Returns:
        An ExecResult with the exit code and captured output when the process ran to
        completion, or an Err if it could not be started or exceeded `timeout`.
    """
    argv = list(command)
    if not argv:
        return Err("no command given")
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=dict(env) if env is not None else None,
            stdin=subprocess.PIPE if stdin is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        return Err(f"command not found: {argv[0]}")
    except PermissionError:
        return Err(f"permission denied: {argv[0]}")
    except OSError as exc:
        return Err(f"could not start {argv[0]}: {exc}")

    assert process.stdout is not None and process.stderr is not None
    out = _Tee(process.stdout, sys.stdout if stream_stdout else None)
    err = _Tee(process.stderr, sys.stderr if stream_stderr else None)
    readers = [threading.Thread(target=out.drain), threading.Thread(target=err.drain)]
    for reader in readers:
        reader.start()
    # Feed stdin after the readers are draining, so a command that writes before it
    # finishes reading cannot deadlock on a full stdout/stderr pipe.
    if stdin is not None and process.stdin is not None:
        try:
            process.stdin.write(stdin)
            process.stdin.close()
        except OSError:
            pass  # the process exited before reading stdin; its exit code reports it
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()  # closes the pipes, so the reader threads reach EOF and exit
        process.wait()
        for reader in readers:
            reader.join()
        return Err(f"timed out after {timeout} seconds: {argv[0]}", timed_out=True)
    for reader in readers:
        reader.join()
    if check and process.returncode != 0:
        reason = err.captured.strip() or f"{argv[0]} exited {process.returncode}"
        return Err(reason)
    return ExecResult(
        exit_code=process.returncode, stdout=out.captured, stderr=err.captured
    )

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the subprocess runner (reposcan.execution.process)."""

import io
import sys
from contextlib import redirect_stderr, redirect_stdout

from reposcan.execution.process import ExecResult, Failure, run_process


def test_captures_output_exit_code_and_check() -> None:
    result = run_process(
        [sys.executable, "-c", "import sys; print('o'); sys.stderr.write('e'); exit(3)"]
    )
    assert isinstance(result, ExecResult)
    assert result.stdout.strip() == "o" and "e" in result.stderr
    assert result.exit_code == 3
    # check turns a nonzero exit into a Failure; a zero exit stays an ExecResult.
    assert isinstance(run_process([sys.executable, "-c", ""], check=True), ExecResult)
    bad = run_process([sys.executable, "-c", "raise SystemExit(3)"], check=True)
    assert isinstance(bad, Failure)


def test_stdin_is_fed_to_the_command() -> None:
    result = run_process(
        [sys.executable, "-c", "import sys; print(sys.stdin.read())"],
        stdin="piped-input",
    )
    assert isinstance(result, ExecResult)
    assert result.stdout.strip() == "piped-input"


def test_the_ways_a_run_can_fail_become_failures() -> None:
    assert isinstance(run_process([]), Failure)  # no command
    missing = run_process(["reposcan-no-such-binary-xyz"])
    assert isinstance(missing, Failure) and not missing.timed_out
    sleep = [sys.executable, "-c", "import time; time.sleep(5)"]
    slow = run_process(sleep, timeout=0.5)
    assert isinstance(slow, Failure) and slow.timed_out


def test_streams_tee_output_live_while_still_capturing_and_reporting_failures() -> None:
    program = "import sys; print('out'); sys.stderr.write('err\\n'); exit(4)"
    live_out, live_err = io.StringIO(), io.StringIO()
    with redirect_stdout(live_out), redirect_stderr(live_err):
        result = run_process(
            [sys.executable, "-c", program], stream_stdout=True, stream_stderr=True
        )
    assert isinstance(result, ExecResult) and result.exit_code == 4
    assert result.stdout.strip() == "out" and result.stderr.strip() == "err"  # captured
    assert "out" in live_out.getvalue() and "err" in live_err.getvalue()  # echoed live

    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        failing = "import sys; sys.stderr.write('no such file\\n'); raise SystemExit(3)"
        bad = run_process(
            [sys.executable, "-c", failing], check=True, stream_stderr=True
        )
        sleep = [sys.executable, "-c", "import time; time.sleep(5)"]
        slow = run_process(sleep, timeout=0.5, stream_stderr=True)
    # bad's reason is the captured stderr, even though it was also shown live.
    assert isinstance(bad, Failure) and "no such file" in bad.reason
    assert isinstance(slow, Failure) and slow.timed_out

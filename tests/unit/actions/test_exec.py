# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the `reposcan exec` action (reposcan.actions.exec)."""

import io
import sys
from contextlib import redirect_stdout

from reposcan.actions.exec import TIMEOUT_EXIT_CODE, execute
from reposcan.execution.local import LocalContext


def test_forwards_output_and_the_commands_own_exit_code() -> None:
    out = io.StringIO()
    with redirect_stdout(out):
        code = execute(
            LocalContext(),
            [sys.executable, "-c", "print('X'); raise SystemExit(7)"],
            timeout=None,
        )
    assert code == 7
    assert "X" in out.getvalue()


def test_maps_the_failure_modes_to_exit_codes() -> None:
    local = LocalContext()
    assert execute(local, [], timeout=None) == 2  # no command given
    assert execute(local, ["reposcan-no-such-binary-xyz"], timeout=None) == 1  # start
    slept = [sys.executable, "-c", "import time; time.sleep(5)"]
    assert execute(local, slept, timeout=0.5) == TIMEOUT_EXIT_CODE  # timed out

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the local execution context (reposcan.execution.local)."""

import os
import sys
import tempfile

from reposcan.execution.context import read_file, write_file
from reposcan.execution.local import LocalContext
from reposcan.execution.process import ExecResult


def test_run_executes_on_the_host_with_env_overlaid() -> None:
    result = LocalContext().run(
        [sys.executable, "-c", "import os; print(os.environ['REPOSCAN_TEST_VAR'])"],
        env={"REPOSCAN_TEST_VAR": "overlaid"},
    )
    assert isinstance(result, ExecResult)
    assert result.stdout.strip() == "overlaid"


def test_write_file_feeds_content_over_stdin_and_read_file_reads_it_back() -> None:
    ctx = LocalContext()
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "lock.txt")
        assert write_file(ctx, path, "flask==3.0.0\nrequests==2.31.0\n") is True
        assert read_file(ctx, path) == "flask==3.0.0\nrequests==2.31.0\n"


def test_a_tool_root_is_prepended_to_path_so_exec_finds_tools() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        ctx = LocalContext(tool_root=tmp)
        result = ctx.run([sys.executable, "-c", "import os; print(os.environ['PATH'])"])
    assert isinstance(result, ExecResult)
    assert result.stdout.strip().startswith(f"{tmp}{os.pathsep}")

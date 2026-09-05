# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the local execution context (reposcan.execution.local)."""

import os
import sys
import tempfile

from reposcan.execution.context import read_file, write_file
from reposcan.execution.local import LocalContext
from reposcan.result import Err


def test_run_executes_on_the_host_with_env_overlaid() -> None:
    result = LocalContext().run(
        [sys.executable, "-c", "import os; print(os.environ['REPOSCAN_TEST_VAR'])"],
        env={"REPOSCAN_TEST_VAR": "overlaid"},
    )
    assert not isinstance(result, Err)
    assert result.stdout.strip() == "overlaid"


def test_write_file_feeds_content_over_stdin_and_read_file_reads_it_back() -> None:
    ctx = LocalContext()
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "lock.txt")
        assert write_file(ctx, path, "flask==3.0.0\nrequests==2.31.0\n") is None
        assert read_file(ctx, path) == "flask==3.0.0\nrequests==2.31.0\n"


def test_a_bin_dir_is_prepended_to_path_so_exec_finds_tools() -> None:
    show_path = [sys.executable, "-c", "import os; print(os.environ['PATH'])"]
    with tempfile.TemporaryDirectory() as tmp:
        ctx = LocalContext(bin_dir=tmp)
        result = ctx.run(show_path)
        assert not isinstance(result, Err)
        assert result.stdout.strip().startswith(f"{tmp}{os.pathsep}")

        # A caller's own PATH is prefixed rather than discarded.
        result = ctx.run(show_path, env={"PATH": "/custom"})
        assert not isinstance(result, Err)
        assert result.stdout.strip() == f"{tmp}{os.pathsep}/custom"

        # With nothing to prepend to, no trailing separator: an empty element on
        # PATH means the cwd, which is the repository under scan.
        result = ctx.run(show_path, env={"PATH": ""})
        assert not isinstance(result, Err)
        assert result.stdout.strip() == tmp


def test_the_host_environment_is_filtered_to_the_allowlist() -> None:
    os.environ["REPOSCAN_TEST_SECRET"] = "secret"
    os.environ["LANG"] = "C.UTF-8"  # an allowlisted name, set here so the test owns it
    try:
        result = LocalContext().run(
            [sys.executable, "-c", "import os; print('\\n'.join(os.environ))"]
        )
    finally:
        del os.environ["REPOSCAN_TEST_SECRET"]
        del os.environ["LANG"]
    assert not isinstance(result, Err)
    passed = result.stdout.split()
    assert "REPOSCAN_TEST_SECRET" not in passed
    assert "LANG" in passed  # allowlisted names still reach the tool


def test_added_variables_reach_the_tool_alongside_the_allowlist() -> None:
    ctx = LocalContext(env={"REPOSCAN_TEST_EXTRA": "passed"})
    result = ctx.run(
        [sys.executable, "-c", "import os; print(os.environ['REPOSCAN_TEST_EXTRA'])"]
    )
    assert not isinstance(result, Err)
    assert result.stdout.strip() == "passed"

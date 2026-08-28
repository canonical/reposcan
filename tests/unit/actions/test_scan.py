# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the scan command (repo_scanner.actions.scan.ScanCommand).

`run_scan` and `start_session` are patched; these tests cover only the command itself:
selecting scans, consolidating artifacts, writing reports, and choosing the exit code.
"""

import io
import json
import os
import tempfile
from collections.abc import Sequence
from contextlib import redirect_stdout

import pytest

import repo_scanner.actions.scan as scan_cmd
from repo_scanner.cli_kit import params_of
from repo_scanner.db import read as db_read
from repo_scanner.execution.process import Failure
from repo_scanner.output import Format
from repo_scanner.scans import sarif
from repo_scanner.scans.registry import SCANS
from repo_scanner.scans.repo import ProjectIdentity, RepositoryState
from tests.unit.actions.helpers import patch_run_scan, sarif_run


def _run(
    *outcomes: sarif.SarifRun | Failure,
    scans: Sequence[str] = ("secrets",),
    fmt: Format | None = None,
) -> tuple[int, str]:
    # `scans` is passed already parsed (a list), as the CLI's converter would produce.
    out = io.StringIO()
    with tempfile.TemporaryDirectory() as repo:
        action = scan_cmd.ScanCommand(
            scans=list(scans), path=repo, format=fmt.value if fmt else None
        )
        with patch_run_scan(scan_cmd, *outcomes), redirect_stdout(out):
            code = action.run()
    return code, out.getvalue()


def test_exit_zero_when_no_findings_and_three_when_findings() -> None:
    code, out = _run(sarif_run(0))
    assert code == 0
    assert "LEVEL" in out  # the default stdout table's header
    code, _ = _run(sarif_run(2))
    assert code == 3  # findings


def test_format_json_overrides_the_stdout_table_default() -> None:
    code, out = _run(sarif_run(1), fmt=Format.JSON)
    assert code == 3
    assert json.loads(out)["version"] == "2.1.0"  # native SARIF, not a table


def test_a_scan_failure_returns_one() -> None:
    code, _ = _run(Failure(reason="trufflehog failed"))
    assert code == 1


def test_multiple_scans_combine_into_one_report_without_cross_scan_dedup() -> None:
    # Two SARIF scans run; their artifacts combine into one multi-run report. Each scan
    # stays its own run, so identical findings from different scans are not deduped.
    code, out = _run(sarif_run(1), sarif_run(1), scans=["sast", "secrets"])
    assert code == 3
    finding_rows = [line for line in out.splitlines() if "f.py:" in line]
    assert len(finding_rows) == 2  # one finding per scan, kept separate


def test_output_file_receives_the_report_and_stdout_stays_clean() -> None:
    with tempfile.TemporaryDirectory() as repo:
        path = os.path.join(repo, "report.sarif")
        action = scan_cmd.ScanCommand(scans=["secrets"], path=repo, output=path)
        out = io.StringIO()
        with patch_run_scan(scan_cmd, sarif_run(1)), redirect_stdout(out):
            code = action.run()
        assert code == 3
        assert out.getvalue() == ""  # nothing on stdout when writing to a file
        with open(path, encoding="ascii") as handle:
            written = json.loads(handle.read())
        assert written["version"] == "2.1.0"


def test_refuses_to_overwrite_an_existing_output_file() -> None:
    with tempfile.TemporaryDirectory() as repo:
        path = os.path.join(repo, "report.sarif")
        with open(path, "w", encoding="ascii") as handle:
            handle.write("existing report")
        action = scan_cmd.ScanCommand(scans=["secrets"], path=repo, output=path)
        out = io.StringIO()
        with patch_run_scan(scan_cmd, sarif_run(1)), redirect_stdout(out):
            code = action.run()
        assert code == 2  # refused before running the scan
        assert out.getvalue() == ""
        with open(path, encoding="ascii") as handle:
            assert handle.read() == "existing report"  # untouched


def test_db_records_the_analysis_and_composes_with_an_output_file() -> None:
    with tempfile.TemporaryDirectory() as directory:
        database = os.path.join(directory, "history.db")
        report = os.path.join(directory, "report.sarif")
        action = scan_cmd.ScanCommand(
            scans=["secrets"], path=directory, output=report, db=database
        )
        # The fake session has no context to run git in, so name the repository here.
        saved = scan_cmd.read_repository_state
        scan_cmd.read_repository_state = lambda ctx, target: RepositoryState(
            identity=ProjectIdentity("acme")
        )
        try:
            with patch_run_scan(scan_cmd, sarif_run(1)):
                code = action.run()
        finally:
            scan_cmd.read_repository_state = saved
        # -o and --db are independent: passing both emits the report and records it.
        assert code == 3
        assert os.path.exists(report)
        (analysis,) = db_read.analyses(database)
        assert analysis.categories == ("secrets",)
        (project,) = db_read.projects(database)
        assert project.name == "acme"
        assert len(db_read.issues(database, project.project_id)) == 1


def test_scan_names_splits_dedups_strips_and_rejects() -> None:
    # The `scans` positional's converter runs at parse time: split on commas, strip
    # whitespace, drop empties, dedup in order; reject unknown or empty input.
    assert scan_cmd._scan_names(" sast , sast, ,secrets ") == ["sast", "secrets"]
    for bad in (" , ", "sast,bogus"):
        with pytest.raises(ValueError):
            scan_cmd._scan_names(bad)


def test_scan_names_all_expands_to_every_scan() -> None:
    # `all` expands to every scan type, deduping against any also named explicitly.
    assert scan_cmd._scan_names("all") == list(SCANS)
    rest = [name for name in SCANS if name != "sast"]
    assert scan_cmd._scan_names("sast,all") == ["sast", *rest]


def test_scan_command_aggregates_scan_options_with_requires() -> None:
    # Every scan's own options are aggregated onto the command (so they parse and
    # populate self.<name>), and each requires the scan(s) that declare it to be among
    # the selected `scans` -- so `--depth` without `secrets` is a usage error.
    aggregated = {param.name: param for param in scan_cmd.ScanCommand.extra_options}
    declared = {param.name for param in params_of(scan_cmd.ScanCommand)}
    for scan_name, scan_class in SCANS.items():
        for param in params_of(scan_class):
            assert param.name in declared, f"{scan_class.__name__}.{param.name}"
            requires = aggregated[param.name].requires
            assert requires is not None
            owners = requires["scans"]
            owners = owners if isinstance(owners, tuple) else (owners,)
            assert scan_name in owners

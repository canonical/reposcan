# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the scan run/emit flow (repo_scanner.scans.base.ScanAction.run).

`run_scan` and `start_session` are patched, so this covers the action's own job:
resolving the report, writing it, and choosing the exit code (0 clean / 3 findings /
1 error / 2 for a bad path or an existing output file).
"""

import io
import json
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager, redirect_stdout
from typing import cast

import repo_scanner.scans.base as base
from repo_scanner.execution.context import ExecutionContext
from repo_scanner.execution.process import Failure
from repo_scanner.scans import cyclonedx, sarif
from repo_scanner.scans.model import Artifact
from repo_scanner.scans.output import Format
from repo_scanner.scans.secrets import SecretsScan


def _sarif_artifact(findings: int) -> Artifact:
    results = [
        sarif.SarifResult.build("AWS", "secret", "f.py", 1, "trufflehog", "/scan/x")
        for _ in range(findings)
    ]
    return sarif.SarifDocument.from_results("trufflehog", "3.95.8", results)


def _sbom_artifact(components: int) -> Artifact:
    listed = [{"name": f"c{i}"} for i in range(components)]
    return cyclonedx.CycloneDxDocument({"bomFormat": "CycloneDX", "components": listed})


class _FakeSession:
    """A started session over a placeholder context (run_scan is patched away)."""

    ok = True
    exit_code = 0
    context = cast(ExecutionContext, None)
    target = "/scan/x"
    tool_root = "/opt/reposcan"
    resolved_parent = ""

    def __enter__(self) -> "_FakeSession":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


@contextmanager
def _patched(outcome: Artifact | Failure) -> Iterator[None]:
    """Patch base.run_scan to a scripted outcome and base.start_session to a fake."""
    saved_run, saved_session = base.run_scan, base.start_session
    base.run_scan = lambda *args, **kwargs: outcome
    base.start_session = lambda *args, **kwargs: _FakeSession()
    try:
        yield
    finally:
        base.run_scan, base.start_session = saved_run, saved_session


def _run(
    outcome: Artifact | Failure,
    *,
    fmt: Format | None = None,
) -> tuple[int, str]:
    out = io.StringIO()
    with tempfile.TemporaryDirectory() as repo:
        action = SecretsScan(path=repo, format=fmt.value if fmt else None)
        with _patched(outcome), redirect_stdout(out):
            code = action.run()
    return code, out.getvalue()


def test_sbom_artifact_always_exits_zero() -> None:
    # An SBOM is an inventory, not pass/fail: even with components it exits 0.
    code, out = _run(_sbom_artifact(5))
    assert code == 0
    assert "COMPONENT" in out and "c0" in out  # the default stdout table


def test_exit_zero_when_no_findings_and_three_when_findings() -> None:
    code, out = _run(_sarif_artifact(0))
    assert code == 0
    assert "LEVEL" in out  # the default stdout table's header
    code, _ = _run(_sarif_artifact(2))
    assert code == 3  # findings


def test_format_json_overrides_the_stdout_table_default() -> None:
    code, out = _run(_sarif_artifact(1), fmt=Format.JSON)
    assert code == 3
    assert json.loads(out)["version"] == "2.1.0"  # native SARIF, not a table


def test_a_scan_failure_returns_one() -> None:
    code, _ = _run(Failure(reason="trufflehog failed"))
    assert code == 1


def test_output_file_receives_the_report_and_stdout_stays_clean() -> None:
    with tempfile.TemporaryDirectory() as repo:
        path = os.path.join(repo, "report.sarif")
        action = SecretsScan(path=repo, output=path)
        out = io.StringIO()
        with _patched(_sarif_artifact(1)), redirect_stdout(out):
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
        action = SecretsScan(path=repo, output=path)
        out = io.StringIO()
        with _patched(_sarif_artifact(1)), redirect_stdout(out):
            code = action.run()
        assert code == 2  # refused before running the scan
        assert out.getvalue() == ""
        with open(path, encoding="ascii") as handle:
            assert handle.read() == "existing report"  # untouched

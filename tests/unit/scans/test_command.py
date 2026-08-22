# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the scan command.

`run_scan` and `start_session` are patched; these tests covers only command itself:
selecting scans, consolidating artifacts, writing reports, and choosing the exit
code.
"""

import io
import json
import os
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, redirect_stdout
from typing import cast

import pytest

import repo_scanner.scans.command as command
from repo_scanner.cli_kit import params_of
from repo_scanner.execution.context import ExecutionContext
from repo_scanner.execution.process import Failure
from repo_scanner.scans import cyclonedx, sarif
from repo_scanner.scans.command import SCANS
from repo_scanner.scans.model import Artifact, ToolInvocationRecord
from repo_scanner.scans.output import Format


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
def _patched_run_scan(*outcomes: Artifact | Failure) -> Iterator[None]:
    """Patch command.run_scan to return `outcomes` in turn, start_session to a fake."""
    remaining = list(outcomes)
    saved_run, saved_session = command.run_scan, command.start_session

    def fake_run_scan(*args: object, **kwargs: object) -> Artifact | Failure:
        return remaining.pop(0)

    command.run_scan = fake_run_scan
    command.start_session = lambda *args, **kwargs: _FakeSession()
    try:
        yield
    finally:
        command.run_scan, command.start_session = saved_run, saved_session


def _run(
    *outcomes: Artifact | Failure,
    scans: Sequence[str] = ("secrets",),
    fmt: Format | None = None,
) -> tuple[int, str]:
    # `scans` is passed already parsed (a list), as the CLI's converter would produce.
    out = io.StringIO()
    with tempfile.TemporaryDirectory() as repo:
        action = command.ScanCommand(
            scans=list(scans), path=repo, format=fmt.value if fmt else None
        )
        with _patched_run_scan(*outcomes), redirect_stdout(out):
            code = action.run()
    return code, out.getvalue()


def test_sbom_artifact_always_exits_zero() -> None:
    # An SBOM is an inventory, not pass/fail: even with components it exits 0.
    code, out = _run(_sbom_artifact(5), scans=["sbom"])
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


def test_multiple_scans_consolidate_to_one_findings_report() -> None:
    # Two SARIF scans run; their artifacts merge into a single findings table.
    code, out = _run(_sarif_artifact(1), _sarif_artifact(1), scans=["sast", "secrets"])
    assert code == 3
    finding_rows = [line for line in out.splitlines() if "f.py:" in line]
    assert len(finding_rows) == 1  # the two identical findings deduped into one


def test_findings_and_sbom_to_one_json_file_is_a_usage_error() -> None:
    # A mixed run (findings + SBOM) cannot share one JSON file; caught before scanning.
    with tempfile.TemporaryDirectory() as repo:
        path = os.path.join(repo, "report.sarif")
        action = command.ScanCommand(scans=["sast", "sbom"], path=repo, output=path)
        with _patched_run_scan(_sarif_artifact(1), _sbom_artifact(1)):
            code = action.run()
        assert code == 2  # usage error: needs --format sqlite (fail-fast, pre-scan)
        assert not os.path.exists(path)


def test_findings_and_sbom_as_json_to_stdout_is_a_usage_error() -> None:
    # Two documents cannot share stdout as JSON either (a table stream would be fine).
    code, _ = _run(
        _sarif_artifact(1), _sbom_artifact(1), scans=["sast", "sbom"], fmt=Format.JSON
    )
    assert code == 2


def test_findings_and_sbom_together_print_both_tables_on_stdout() -> None:
    code, out = _run(_sarif_artifact(1), _sbom_artifact(1), scans=["sast", "sbom"])
    assert code == 3  # a findings scan reported something
    assert "LEVEL" in out and "COMPONENT" in out  # both tables rendered


def test_output_file_receives_the_report_and_stdout_stays_clean() -> None:
    with tempfile.TemporaryDirectory() as repo:
        path = os.path.join(repo, "report.sarif")
        action = command.ScanCommand(scans=["secrets"], path=repo, output=path)
        out = io.StringIO()
        with _patched_run_scan(_sarif_artifact(1)), redirect_stdout(out):
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
        action = command.ScanCommand(scans=["secrets"], path=repo, output=path)
        out = io.StringIO()
        with _patched_run_scan(_sarif_artifact(1)), redirect_stdout(out):
            code = action.run()
        assert code == 2  # refused before running the scan
        assert out.getvalue() == ""
        with open(path, encoding="ascii") as handle:
            assert handle.read() == "existing report"  # untouched


def test_scan_names_splits_dedups_strips_and_rejects() -> None:
    # The `scans` positional's converter runs at parse time: split on commas, strip
    # whitespace, drop empties, dedup in order; reject unknown or empty input.
    assert command._scan_names(" sast , sast, ,secrets ") == ["sast", "secrets"]
    for bad in (" , ", "sast,bogus"):
        with pytest.raises(ValueError):
            command._scan_names(bad)


def test_scan_names_all_expands_to_every_scan() -> None:
    # `all` expands to every scan type, deduping against any also named explicitly.
    assert command._scan_names("all") == list(SCANS)
    rest = [name for name in SCANS if name != "sast"]
    assert command._scan_names("sast,all") == ["sast", *rest]


def test_scan_command_aggregates_scan_options_with_requires() -> None:
    # Every scan's own options are aggregated onto the command (so they parse and
    # populate self.<name>), and each requires the scan(s) that declare it to be among
    # the selected `scans` -- so `--depth` without `secrets` is a usage error.
    aggregated = {param.name: param for param in command.ScanCommand.extra_options}
    declared = {param.name for param in params_of(command.ScanCommand)}
    for scan_name, scan_class in SCANS.items():
        for param in params_of(scan_class):
            assert param.name in declared, f"{scan_class.__name__}.{param.name}"
            requires = aggregated[param.name].requires
            assert requires is not None
            owners = requires["scans"]
            owners = owners if isinstance(owners, tuple) else (owners,)
            assert scan_name in owners


def _consolidate(*artifacts: Artifact) -> Sequence[Artifact]:
    return command._consolidate(list(artifacts))


def test_consolidate_groups_by_kind() -> None:
    # SARIF artifacts merge together; a CycloneDX stays separate; at most one per kind.
    consolidated = _consolidate(
        _sarif_artifact(1), _sbom_artifact(1), _sarif_artifact(1)
    )
    kinds = [artifact.kind for artifact in consolidated]
    assert kinds == [sarif.SarifDocument.kind, cyclonedx.CycloneDxDocument.kind]


def test_consolidate_preserves_each_scan_s_invocations() -> None:
    # Merging two findings scans keeps both scans' recorded tool invocations.
    first, second = _sarif_artifact(1), _sarif_artifact(1)
    first.record_invocations(
        [ToolInvocationRecord(tool="trivy", args=[], command=("trivy",))]
    )
    second.record_invocations(
        [ToolInvocationRecord(tool="grype", args=[], command=("grype",))]
    )
    (merged,) = _consolidate(first, second)
    invocations = merged.to_dict()["runs"][0].get("invocations", [])
    tools = [inv["properties"]["tool"] for inv in invocations]
    assert tools == ["trivy", "grype"]

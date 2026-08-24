# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""SARIF tests.scans.sarif)."""

import hashlib
import json
from typing import cast

from repo_scanner.execution.context import ExecutionContext
from repo_scanner.execution.process import ExecResult
from repo_scanner.scans import sarif
from repo_scanner.scans.model import ToolInvocationRecord


def test_build_creates_a_finding_normalized_at_construction() -> None:
    finding = sarif.SarifResult.build(
        "AWS",
        "leaked key",
        "/scan/repo/src/app.py",
        12,
        "trufflehog",
        "/scan/repo",
        level="error",
    )
    assert finding.rule_id == "AWS"
    assert finding.message == "leaked key"
    assert finding.uri == "src/app.py"  # relativized at creation
    assert finding.line == 12
    assert finding.location == "src/app.py:12"
    assert finding.level == "error"
    assert finding.scanners == ["trufflehog"]  # annotated at creation
    assert finding.key == ("AWS", "src/app.py", 12)


def test_from_runs_wraps_a_run_built_from_results() -> None:
    finding = sarif.SarifResult.build(
        "AWS", "k", "/scan/repo/src/app.py", 3, "trufflehog", "/scan/repo"
    )
    run = sarif.SarifRun.from_results("trufflehog", "1.0", [finding])
    doc = sarif.SarifDocument.from_runs([run])
    (assembled,) = doc.results()
    assert assembled.uri == "src/app.py"  # already relative from build
    assert assembled.scanners == ["trufflehog"]
    assert doc.to_dict()["runs"][0]["tool"]["driver"]["name"] == "trufflehog"


def test_parse_normalizes_each_result_at_ingestion() -> None:
    text = json.dumps(
        {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "rules": [
                                {"id": "R", "defaultConfiguration": {"level": "error"}}
                            ]
                        }
                    },
                    "results": [
                        {
                            "ruleId": "R",
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "file:///scan/repo/x.py"
                                        },
                                        "region": {"startLine": 4},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ]
        }
    )
    doc = sarif.parse(text, "semgrep", "/scan/repo")
    assert doc is not None
    (finding,) = doc.results()
    assert finding.uri == "x.py"  # file:// scheme and target prefix stripped
    assert finding.scanners == ["semgrep"]  # scanner annotated on ingest
    assert finding.level == "error"  # inherited from the rule's configuration


def test_parse_relativizes_every_location_not_just_the_primary() -> None:
    def _loc(uri: str) -> dict:
        return {"physicalLocation": {"artifactLocation": {"uri": uri}}}

    text = json.dumps(
        {
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "R",
                            "level": "warning",
                            "locations": [
                                _loc("/scan/repo/a.py"),
                                _loc("/scan/repo/nested/b.py"),
                            ],
                        }
                    ]
                }
            ]
        }
    )
    doc = sarif.parse(text, "semgrep", "/scan/repo")
    assert doc is not None
    (result,) = doc.results()
    uris = [
        location["physicalLocation"]["artifactLocation"]["uri"]
        for location in result.result["locations"]  # raw dict: all locations, not [0]
    ]
    assert uris == ["a.py", "nested/b.py"]  # both locations relativized, not just [0]


def test_add_primarylocationlinehash() -> None:
    class _Ctx:
        def run(self, command: list[str], **kwargs: object) -> ExecResult:
            return ExecResult(0, "import os\nSECRET = 'abc'\n", "")

    region = {"startLine": 2, "snippet": {"text": "    other = 'text'"}}
    physical = {"artifactLocation": {"uri": "x.py"}, "region": region}
    result = {
        "ruleId": "R",
        "level": "warning",
        "locations": [{"physicalLocation": physical}],
    }
    doc = sarif.parse(json.dumps({"runs": [{"results": [result]}]}), "semgrep", "/r")
    assert doc is not None
    (run,) = doc.runs()
    sarif.add_primarylocationlinehash(run, cast(ExecutionContext, _Ctx()), "/r")
    (finding,) = run.results()
    expected = hashlib.sha256(b"SECRET = 'abc'").hexdigest()[:16]
    assert finding.result["partialFingerprints"]["primaryLocationLineHash"] == expected


def test_add_primarylocationlinehash_skips_when_the_source_is_unreadable() -> None:
    class _Ctx:
        def run(self, command: list[str], **kwargs: object) -> ExecResult:
            return ExecResult(1, "", "")

    finding = sarif.SarifResult.build("AWS", "k", "app.py", 12, "trufflehog", "/r")
    run = sarif.SarifRun.from_results("trufflehog", "1.0", [finding])
    sarif.add_primarylocationlinehash(run, cast(ExecutionContext, _Ctx()), "/r")
    (stored,) = run.results()
    assert "partialFingerprints" not in stored.result


def test_parse_returns_none_for_non_sarif_text() -> None:
    assert sarif.parse("not json", "semgrep", "/scan/repo") is None


def test_merge_runs_dedups_unions_scanners_and_carries_invocations() -> None:
    # Two tool runs report the same finding (same rule and location) plus a unique one;
    # merge_runs dedups the shared finding, unions its scanner list, and carries both
    # runs' recorded tool invocations onto the one merged run.
    shared_a = sarif.SarifResult.build("AWS", "k", "/r/app.py", 1, "trivy", "/r")
    unique = sarif.SarifResult.build("GCP", "k", "/r/other.py", 2, "trivy", "/r")
    shared_b = sarif.SarifResult.build("AWS", "k", "/r/app.py", 1, "grype", "/r")
    first = sarif.SarifRun.from_results("trivy", "1.0", [shared_a, unique])
    second = sarif.SarifRun.from_results("grype", "1.0", [shared_b])
    first.record_invocations(
        [ToolInvocationRecord(tool="trivy", args=[], command=("trivy",))]
    )
    second.record_invocations(
        [ToolInvocationRecord(tool="grype", args=[], command=("grype",))]
    )

    merged = sarif.merge_runs([first, second])

    results = merged.results()
    assert len(results) == 2  # the shared finding is deduped
    (shared,) = [result for result in results if result.rule_id == "AWS"]
    assert sorted(shared.scanners) == ["grype", "trivy"]  # scanner lists unioned
    tools = [inv["properties"]["tool"] for inv in merged.to_dict()["invocations"]]
    assert tools == ["trivy", "grype"]  # each run's invocations carried


def test_from_runs_keeps_one_run_per_scan_without_cross_scan_dedup() -> None:
    # from_runs assembles several scans' consolidated runs into a multi-run report: each
    # scan stays its own run (driver, automationDetails, results) -- no dedup across
    # scans, even when two scans report the same rule and location.
    sast = sarif.SarifRun.from_results(
        "semgrep",
        "1.0",
        [sarif.SarifResult.build("R", "k", "/r/app.py", 1, "semgrep", "/r")],
    )
    sast.set_automation_id("reposcan/sast/")
    secrets = sarif.SarifRun.from_results(
        "trufflehog",
        "1.0",
        [sarif.SarifResult.build("R", "k", "/r/app.py", 1, "trufflehog", "/r")],
    )
    secrets.set_automation_id("reposcan/secrets/")

    report = sarif.SarifDocument.from_runs([sast, secrets])

    runs = report.to_dict()["runs"]
    assert [run["automationDetails"]["id"] for run in runs] == [
        "reposcan/sast/",
        "reposcan/secrets/",
    ]
    assert report.count() == 2  # both kept: no cross-scan dedup

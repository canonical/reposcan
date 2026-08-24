# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the CI/workflow scan (repo_scanner.scans.workflow)."""

import json

from repo_scanner.execution.process import ExecResult, Failure
from repo_scanner.scans import sarif
from repo_scanner.scans.workflow import WorkflowScan


def _result(rule: str, uri: str, line: int) -> dict:
    location = {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}
    return {"ruleId": rule, "locations": [{"physicalLocation": location}]}


def _sarif(results: list[dict]) -> str:
    return json.dumps({"version": "2.1.0", "runs": [{"results": results}]})


def test_create_run_then_merge_dedups_and_annotates_scanners() -> None:
    shared = _result("SHARED", "workflow.yml", 3)
    zizmor = _sarif([shared, _result("ZIZ", "workflow.yml", 5)])
    poutine = _sarif([shared, _result("POU", "workflow.yml", 7)])

    scan = WorkflowScan()
    zizmor_run = scan.create_run("zizmor", ExecResult(0, zizmor, ""), "/scan/acme")
    poutine_run = scan.create_run("poutine", ExecResult(0, poutine, ""), "/scan/acme")
    assert not isinstance(zizmor_run, Failure)
    assert not isinstance(poutine_run, Failure)
    merged = sarif.merge_runs([zizmor_run, poutine_run])
    findings = merged.results()
    assert len(findings) == 3  # the shared finding is deduped
    by_rule = {finding.rule_id: finding for finding in findings}
    assert by_rule["SHARED"].scanners == ["zizmor", "poutine"]
    assert by_rule["ZIZ"].scanners == ["zizmor"]
    assert by_rule["POU"].scanners == ["poutine"]


def test_create_run_fails_when_a_tool_output_is_not_sarif() -> None:
    result = WorkflowScan().create_run(
        "zizmor", ExecResult(0, "not sarif", ""), "/scan/acme"
    )
    assert isinstance(result, Failure)

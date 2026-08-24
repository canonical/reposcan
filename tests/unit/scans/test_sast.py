# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the SAST scan (repo_scanner.scans.sast)."""

import json
from typing import cast

from repo_scanner.execution.context import ExecutionContext
from repo_scanner.execution.process import ExecResult, Failure
from repo_scanner.scans.model import ArtifactKind
from repo_scanner.scans.sast import SastScan


def test_invocations_run_semgrep_producing_sarif() -> None:
    inv = SastScan().invocations(cast(ExecutionContext, None), "/scan/acme")[0]
    assert inv.tool == "semgrep"
    assert "--sarif" in inv.args
    assert inv.args[-1] == "/scan/acme"  # the target is the last argument


def test_parse_normalizes_semgrep_sarif() -> None:
    # parse ingests one semgrep run's SARIF and normalizes it (merge is covered in
    # test_workflow); the semgrep finding survives with its scanner annotation.
    document = {
        "version": "2.1.0",
        "runs": [{"results": [{"ruleId": "x", "level": "error"}]}],
    }
    result = SastScan().parse(
        "semgrep", ExecResult(0, json.dumps(document), ""), "/scan/acme"
    )
    assert not isinstance(result, Failure)
    assert result.kind is ArtifactKind.SARIF
    findings = result.results()
    assert len(findings) == 1
    assert findings[0].rule_id == "x" and findings[0].level == "error"
    assert findings[0].scanners == ["semgrep"]  # annotated on ingest


def test_parse_rejects_non_sarif_output() -> None:
    result = SastScan().parse(
        "semgrep", ExecResult(0, "not sarif output", ""), "/scan/acme"
    )
    assert isinstance(result, Failure)

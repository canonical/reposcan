# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the SAST scan (reposcan.scans.sast)."""

import json
from typing import cast

from reposcan.execution.context import ExecutionContext
from reposcan.execution.process import ExecResult, Failure
from reposcan.scans.sast import SastScan


def test_invocations_run_semgrep_producing_sarif() -> None:
    inv = SastScan().invocations(cast(ExecutionContext, None), "/scan/acme")[0]
    assert inv.tool == "semgrep"
    assert "--sarif" in inv.args
    assert inv.args[-1] == "/scan/acme"  # the target is the last argument


def test_create_run_normalizes_semgrep_sarif() -> None:
    # create_run ingests one semgrep run's SARIF and normalizes it; the semgrep
    # finding survives with its scanner annotation.
    document = {
        "version": "2.1.0",
        "runs": [{"results": [{"ruleId": "x", "level": "error"}]}],
    }
    run = SastScan().create_run(
        "semgrep", ExecResult(0, json.dumps(document), ""), "/scan/acme"
    )
    assert not isinstance(run, Failure)
    findings = run.results()
    assert len(findings) == 1
    assert findings[0].rule_id == "x" and findings[0].level == "error"
    assert findings[0].scanners == ["semgrep"]  # annotated on ingest


def test_create_run_drops_requires_login_fingerprints() -> None:
    # remove semgrep's matchBasedId/v1 fingerprint placeholder
    document = {
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "only-placeholder",
                        "fingerprints": {"matchBasedId/v1": "requires login"},
                    },
                    {
                        "ruleId": "has-a-real-one",
                        "fingerprints": {
                            "matchBasedId/v1": "requires login",
                            "otherHash": "abc123",
                        },
                        "partialFingerprints": {"p": "requires login"},
                    },
                ]
            }
        ],
    }
    run = SastScan().create_run(
        "semgrep", ExecResult(0, json.dumps(document), ""), "/scan/acme"
    )
    assert not isinstance(run, Failure)
    one, two = run.results()
    assert "fingerprints" not in one.result  # emptied field removed
    assert two.result["fingerprints"] == {"otherHash": "abc123"}
    assert "partialFingerprints" not in two.result  # emptied field removed too


def test_create_run_rejects_non_sarif_output() -> None:
    result = SastScan().create_run(
        "semgrep", ExecResult(0, "not sarif output", ""), "/scan/acme"
    )
    assert isinstance(result, Failure)

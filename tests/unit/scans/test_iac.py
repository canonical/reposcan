# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the IaC scan (repo_scanner.scans.iac)."""

import json

from repo_scanner.execution.process import ExecResult, Failure
from repo_scanner.scans.iac import IacScan


def test_create_run_converts_checkov_failed_checks_to_sarif() -> None:
    report = {
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_DOCKER_3",
                    "check_name": "Ensure a user for the container has been created",
                    "file_path": "/Dockerfile",
                    "file_line_range": [1, 2],
                }
            ]
        }
    }
    run = IacScan().create_run(
        "checkov", ExecResult(0, json.dumps(report), ""), "/scan/acme"
    )
    assert not isinstance(run, Failure)
    finding = run.results()[0]
    assert finding.rule_id == "CKV_DOCKER_3"
    assert finding.uri == "Dockerfile"  # the leading slash is stripped


def test_create_run_rejects_non_json_output() -> None:
    result = IacScan().create_run(
        "checkov", ExecResult(0, "not json", ""), "/scan/acme"
    )
    assert isinstance(result, Failure)

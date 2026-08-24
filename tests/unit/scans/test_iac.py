# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the IaC scan (repo_scanner.scans.iac)."""

import json

from repo_scanner.execution.process import ExecResult, Failure
from repo_scanner.scans.iac import IacScan
from repo_scanner.scans.model import ArtifactKind


def test_parse_converts_checkov_failed_checks_to_sarif() -> None:
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
    result = IacScan().parse(
        "checkov", ExecResult(0, json.dumps(report), ""), "/scan/acme"
    )
    assert not isinstance(result, Failure)
    assert result.kind is ArtifactKind.SARIF
    finding = result.results()[0]
    assert finding.rule_id == "CKV_DOCKER_3"
    assert finding.uri == "Dockerfile"  # the leading slash is stripped


def test_parse_rejects_non_json_output() -> None:
    result = IacScan().parse("checkov", ExecResult(0, "boom", ""), "/scan/acme")
    assert isinstance(result, Failure)

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the SCA scan (repo_scanner.scans.sca), including govulncheck parsing."""

import json

from repo_scanner.execution.process import ExecResult, Failure
from repo_scanner.scans import sarif
from repo_scanner.scans.sca import ScaScan


def test_govulncheck_stream_becomes_sarif() -> None:
    stream = "\n".join(
        [
            json.dumps({"osv": {"id": "GO-2024-1", "summary": "bad thing"}}),
            json.dumps(
                {
                    "finding": {
                        "osv": "GO-2024-1",
                        "trace": [{"position": {"filename": "main.go", "line": 12}}],
                    }
                }
            ),
            json.dumps(
                {"finding": {"osv": "GO-2024-2", "trace": [{}]}}  # no position: skipped
            ),
            json.dumps({"progress": {"message": "scanning"}}),
        ]
    )
    result = ScaScan().parse("govulncheck", ExecResult(3, stream, ""), "/scan/acme")
    assert not isinstance(result, Failure)
    assert result.count() == 1  # only the source-reaching finding
    finding = result.results()[0]
    assert finding.rule_id == "GO-2024-1"
    assert finding.message == "bad thing"  # the OSV summary
    assert finding.scanners == ["govulncheck"]


def test_include_dev_dependencies_adds_the_trivy_flag_only() -> None:
    # Only trivy honors it; grype and govulncheck have no dev/production toggle.
    with_dev = {
        i.tool: i for i in ScaScan(include_dev_dependencies=True).invocations("/x")
    }
    assert "--include-dev-deps" in with_dev["trivy"].args
    default = {i.tool: i for i in ScaScan().invocations("/x")}
    assert "--include-dev-deps" not in default["trivy"].args


def test_consolidate_merges_sarif_tools_with_converted_govulncheck() -> None:
    location = {"artifactLocation": {"uri": "pkg"}, "region": {"startLine": 1}}
    trivy = json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "CVE-1",
                            "locations": [{"physicalLocation": location}],
                        }
                    ]
                }
            ],
        }
    )
    govulncheck = json.dumps(
        {
            "finding": {
                "osv": "GO-1",
                "trace": [{"position": {"filename": "main.go", "line": 2}}],
            }
        }
    )
    scan = ScaScan()
    trivy_doc = scan.parse("trivy", ExecResult(0, trivy, ""), "/scan/acme")
    govulncheck_doc = scan.parse(
        "govulncheck", ExecResult(3, govulncheck, ""), "/scan/acme"
    )
    assert not isinstance(trivy_doc, Failure)
    assert not isinstance(govulncheck_doc, Failure)
    result = scan.consolidate([trivy_doc, govulncheck_doc])
    assert isinstance(result, sarif.SarifDocument)
    rules = {r.rule_id for r in result.results()}
    assert rules == {"CVE-1", "GO-1"}


def test_parse_fails_when_a_sarif_tool_output_is_unusable() -> None:
    result = ScaScan().parse("grype", ExecResult(0, "not sarif", ""), "/scan/acme")
    assert isinstance(result, Failure)

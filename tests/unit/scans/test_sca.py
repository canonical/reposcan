# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the SCA scan (repo_scanner.scans.sca), including govulncheck parsing."""

import json
from typing import cast

from repo_scanner.execution.context import ExecutionContext
from repo_scanner.execution.process import ExecResult, Failure
from repo_scanner.scans import sarif
from repo_scanner.scans.sca import ScaScan

# The SCA scan ignores the context when building its invocations.
_NO_CTX = cast(ExecutionContext, None)


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
    run = ScaScan().create_run("govulncheck", ExecResult(3, stream, ""), "/scan/acme")
    assert not isinstance(run, Failure)
    findings = run.results()
    assert len(findings) == 1  # only the source-reaching finding
    finding = findings[0]
    assert finding.rule_id == "GO-2024-1"
    assert finding.message == "bad thing"  # the OSV summary
    assert finding.scanners == ["govulncheck"]


def test_include_dev_dependencies_adds_the_trivy_flag_only() -> None:
    # Only trivy honors it; grype and govulncheck have no dev/production toggle.
    with_dev = {
        i.tool: i
        for i in ScaScan(include_dev_dependencies=True).invocations(_NO_CTX, "/x")
    }
    assert "--include-dev-deps" in with_dev["trivy"].args
    default = {i.tool: i for i in ScaScan().invocations(_NO_CTX, "/x")}
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
    trivy_run = scan.create_run("trivy", ExecResult(0, trivy, ""), "/scan/acme")
    govulncheck_run = scan.create_run(
        "govulncheck", ExecResult(3, govulncheck, ""), "/scan/acme"
    )
    assert not isinstance(trivy_run, Failure)
    assert not isinstance(govulncheck_run, Failure)
    merged = sarif.merge_runs([trivy_run, govulncheck_run])
    rules = {finding.rule_id for finding in merged.results()}
    assert rules == {"CVE-1", "GO-1"}


def test_create_run_fails_when_a_sarif_tool_output_is_unusable() -> None:
    result = ScaScan().create_run("grype", ExecResult(0, "not sarif", ""), "/scan/acme")
    assert isinstance(result, Failure)

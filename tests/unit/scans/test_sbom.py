# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the SBOM scan (repo_scanner.scans.sbom) and CycloneDX merge."""

import json
from typing import cast

from repo_scanner.execution.context import ExecutionContext
from repo_scanner.execution.process import ExecResult, Failure
from repo_scanner.scans.cyclonedx import CycloneDxDocument
from repo_scanner.scans.model import ToolInvocationRecord
from repo_scanner.scans.sbom import SbomScan

# The SBOM scan ignores the context when building its invocations.
_NO_CTX = cast(ExecutionContext, None)


def _cyclonedx(components: list[dict]) -> str:
    return json.dumps(
        {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": components}
    )


def test_consolidate_merges_dedups_by_purl_and_annotates_scanners() -> None:
    shared = {"type": "library", "name": "left-pad", "purl": "pkg:npm/left-pad@1.0.0"}
    trivy = _cyclonedx([shared, {"name": "a", "purl": "pkg:npm/a@1"}])
    syft = _cyclonedx([shared, {"name": "b", "purl": "pkg:npm/b@1"}])

    scan = SbomScan()
    trivy_doc = scan.parse("trivy", ExecResult(0, trivy, ""), "/scan/acme")
    syft_doc = scan.parse("syft", ExecResult(0, syft, ""), "/scan/acme")
    assert not isinstance(trivy_doc, Failure)
    assert not isinstance(syft_doc, Failure)
    result = scan.consolidate([trivy_doc, syft_doc])
    assert isinstance(result, CycloneDxDocument)
    by_purl = {c["purl"]: c for c in result.components()}
    assert len(by_purl) == 3  # the shared component is deduped by purl
    scanners = [
        p["value"]
        for p in by_purl["pkg:npm/left-pad@1.0.0"]["properties"]
        if p["name"] == "reposcan:scanner"
    ]
    assert scanners == ["trivy", "syft"]


def test_include_dev_dependencies_steers_each_tool() -> None:
    by_tool = {
        i.tool: i
        for i in SbomScan(include_dev_dependencies=True).invocations(_NO_CTX, "/x")
    }
    assert "--include-dev-deps" in by_tool["trivy"].args  # trivy: CLI flag
    syft_env = by_tool["syft"].env or {}
    assert (
        syft_env.get("SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES") == "true"
    )  # syft: env
    assert "--required-only" not in by_tool["cdxgen"].args  # cdxgen: keep its default


def test_dev_dependencies_are_excluded_by_default() -> None:
    by_tool = {i.tool: i for i in SbomScan().invocations(_NO_CTX, "/x")}
    assert "--include-dev-deps" not in by_tool["trivy"].args
    assert "SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES" not in (by_tool["syft"].env or {})
    assert "--required-only" in by_tool["cdxgen"].args  # cdxgen otherwise includes dev


def test_parse_drops_the_scanned_root_component() -> None:
    # Directory scans list a component named "." (or "./") for the scanned root; it is
    # the source, not a dependency, so parse drops it while keeping real packages.
    output = _cyclonedx(
        [
            {"type": "file", "name": "."},
            {"type": "library", "name": "flask", "purl": "pkg:pypi/flask@3.0.0"},
        ]
    )
    result = SbomScan().parse("syft", ExecResult(0, output, ""), "/scan/acme")
    assert not isinstance(result, Failure)
    assert [c["name"] for c in result.components()] == ["flask"]


def test_parse_fails_on_non_cyclonedx_output() -> None:
    result = SbomScan().parse("syft", ExecResult(0, "not cyclonedx", ""), "/scan/acme")
    assert isinstance(result, Failure)


def test_record_invocations_adds_a_formulation_workflow_with_command_and_env() -> None:
    doc = CycloneDxDocument(
        {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
    )
    doc.record_invocations(
        [
            ToolInvocationRecord(
                tool="syft",
                args=[
                    "dir:/scan/acme",
                    "-o",
                    "cyclonedx-json",
                ],
                version="1.46.0",
                command=(
                    "/opt/reposcan/bin/syft",
                    "dir:/scan/acme",
                    "-o",
                    "cyclonedx-json",
                ),
                working_directory="/scan/acme",
                environment={"SYFT_CHECK_FOR_APP_UPDATE": "false"},
                exit_code=0,
                successful=True,
            )
        ]
    )
    (formula,) = doc.to_dict()["formulation"]
    (workflow,) = formula["workflows"]
    assert workflow["taskTypes"] == ["scan"]  # a valid CycloneDX task type
    executed = workflow["steps"][0]["commands"][0]["executed"]
    assert executed == "/opt/reposcan/bin/syft dir:/scan/acme -o cyclonedx-json"
    env_vars = workflow["inputs"][0]["environmentVars"]
    assert {"name": "SYFT_CHECK_FOR_APP_UPDATE", "value": "false"} in env_vars

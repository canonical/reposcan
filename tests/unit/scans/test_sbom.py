# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the SBOM scan (reposcan.scans.sbom) and CycloneDX merge."""

import json
from dataclasses import asdict
from typing import cast

from reposcan.execution.context import ExecutionContext
from reposcan.scans import cyclonedx
from reposcan.scans.cyclonedx import CycloneDxDocument
from reposcan.scans.model import ToolInvocationRecord
from reposcan.scans.sbom import SbomScan

# The SBOM scan ignores the context when building its invocations.
_NO_CTX = cast(ExecutionContext, None)


def _cyclonedx(components: list[dict]) -> str:
    return json.dumps(
        {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": components}
    )


def test_merge_dedups_by_purl_and_annotates_scanners() -> None:
    shared = {"type": "library", "name": "left-pad", "purl": "pkg:npm/left-pad@1.0.0"}
    trivy = _cyclonedx([shared, {"name": "a", "purl": "pkg:npm/a@1"}])
    syft = _cyclonedx([shared, {"name": "b", "purl": "pkg:npm/b@1"}])

    trivy_doc = cyclonedx.parse(trivy, "trivy")
    syft_doc = cyclonedx.parse(syft, "syft")
    assert trivy_doc is not None and syft_doc is not None
    result = cyclonedx.merge([trivy_doc, syft_doc])
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
    result = cyclonedx.parse(output, "syft")
    assert result is not None
    assert [c["name"] for c in result.components()] == ["flask"]


def test_parse_returns_none_on_non_cyclonedx_output() -> None:
    assert cyclonedx.parse("not cyclonedx", "syft") is None


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


def test_recorded_invocations_survive_a_json_round_trip_as_records() -> None:
    # Every field set, so the round trip is checked against the whole record rather
    # than against whichever fields happen not to be at their defaults.
    inv = ToolInvocationRecord(
        tool="govulncheck",
        args=["-format", "sarif", "./..."],
        ok_codes=(0, 3),
        cwd="/scan/x/sub",
        env={"GOFLAGS": "-mod=mod"},
        output_file="govulncheck.json",
        optional=True,
        version="1.1.4",
        command=("/opt/govulncheck", "-format", "sarif", "./...", "--exclude", "v"),
        working_directory="/scan/x/sub",
        environment={"GOFLAGS": "-mod=mod"},
        exit_code=3,
        successful=True,
    )
    doc = CycloneDxDocument({"bomFormat": "CycloneDX", "components": []})
    doc.record_invocations([inv])
    rendered = doc.to_dict()

    # As for SARIF: parsing gives records back, so a document that was read behaves
    # like one that was just produced.
    reread = CycloneDxDocument(json.loads(json.dumps(rendered)))
    (restored,) = reread.tool_invocations
    # Field by field, so a mismatch names the field rather than the whole record.
    assert asdict(restored) == asdict(inv)
    assert reread.to_dict() == rendered  # and rendering again changes nothing


def test_formulation_another_producer_wrote_is_left_alone() -> None:
    theirs = {"bom-ref": "their-build", "workflows": [{"uid": "build-0"}]}
    doc = CycloneDxDocument(
        {"bomFormat": "CycloneDX", "components": [], "formulation": [theirs]}
    )
    # Not under reposcan's bom-ref, so not read as records and not overwritten by the
    # entry reposcan appends.
    assert doc.tool_invocations == []
    doc.record_invocations([ToolInvocationRecord(tool="syft", args=[], version="1.0")])
    refs = [entry["bom-ref"] for entry in doc.to_dict()["formulation"]]
    assert refs == ["their-build", "reposcan-scan"]

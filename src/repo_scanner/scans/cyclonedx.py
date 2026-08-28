# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Parse and merge CycloneDX SBOM documents.

An SBOM lists a repository's software components. SBOM tools each emit CycloneDX
JSON; these helpers merge several into one deduped inventory, annotating each
component with which scanners reported it (via CycloneDX `properties`).
"""

import copy
import json
import shlex
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, ClassVar

from repo_scanner.scans.model import ArtifactKind, ToolInvocationRecord
from repo_scanner.scans.repo import PROPERTY_SCHEMA, RepositoryState

# The property name carrying each contributing scanner on a merged component.
SCANNER_PROPERTY = "reposcan:scanner"

# The formulation entry reposcan writes, and the properties that make each workflow
# in it readable back as a record rather than parsed out of its display strings.
_FORMULATION_REF = "reposcan-scan"
_SCHEMA_PROPERTY = "reposcan:schema"
_REPOSITORY_PROPERTY = "reposcan:repository"
_ANALYSIS_PROPERTY = "reposcan:analysis"
_TOOL_PROPERTY = "reposcan:tool"
_VERSION_PROPERTY = "reposcan:version"
_COMMAND_PROPERTY = "reposcan:command"
_ARGS_PROPERTY = "reposcan:args"
_OK_CODES_PROPERTY = "reposcan:okCodes"
_OPTIONAL_PROPERTY = "reposcan:optional"
_CWD_PROPERTY = "reposcan:cwd"
_ENV_PROPERTY = "reposcan:env"
_OUTPUT_FILE_PROPERTY = "reposcan:outputFile"
_DIRECTORY_PROPERTY = "reposcan:workingDirectory"
_EXIT_CODE_PROPERTY = "reposcan:exitCode"
_SUCCESSFUL_PROPERTY = "reposcan:successful"


@dataclass(frozen=True)
class CycloneDxDocument:
    """A CycloneDX SBOM artifact (an Artifact of kind CYCLONEDX).

    Wraps the rendered CycloneDX `content` (a tool's output, or a `merge`).

    Invocations reposcan recorded are held as `ToolInvocationRecord`s rather than as
    a CycloneDX `formulation`, and `to_dict` renders them back. Constructing a
    document over content that already holds them reads them back out into records,
    so a document that was parsed behaves exactly like one that was just produced.
    Formulation reposcan did not write stays in the content untouched.
    """

    kind: ClassVar[ArtifactKind] = ArtifactKind.CYCLONEDX
    content: dict[str, Any]
    tool_invocations: list[ToolInvocationRecord] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Read reposcan's own workflows out of the formulation and into records."""
        kept: list[dict[str, Any]] = []
        for entry in self.content.get("formulation", []):
            if entry.get("bom-ref") != _FORMULATION_REF:
                kept.append(entry)
                continue
            for workflow in entry.get("workflows", []):
                self.tool_invocations.append(_deserialize_invocation(workflow))
        if "formulation" in self.content:
            self.content["formulation"] = kept

    def to_dict(self) -> dict[str, Any]:
        """The SBOM as a CycloneDX document, with its invocations rendered in."""
        if not self.tool_invocations:
            return self.content
        workflows = [
            _serialize_invocation(index, inv)
            for index, inv in enumerate(self.tool_invocations)
        ]
        return {
            **self.content,
            "formulation": [
                *self.content.get("formulation", []),
                {"bom-ref": _FORMULATION_REF, "workflows": workflows},
            ],
        }

    def components(self) -> list[dict[str, Any]]:
        """Every component object the SBOM lists."""
        return self.content.get("components", [])

    def count(self) -> int:
        """The number of components the SBOM lists."""
        return len(self.components())

    def rows(self) -> tuple[list[str], list[list[str]]]:
        """A table of components: name, version, and type."""
        headers = ["COMPONENT", "VERSION", "TYPE"]
        rows = [
            [
                str(component.get("name", "")),
                str(component.get("version", "")),
                str(component.get("type", "")),
            ]
            for component in self.components()
        ]
        return headers, rows

    def record_provenance(
        self,
        repository: RepositoryState,
        *,
        analysis_uuid: str,
        started_at: str,
        finished_at: str,
        reposcan_version: str,
    ) -> None:
        """Record analysis metadata.

        `metadata.timestamp` and `metadata.tools` are official CycloneDX fields.
        CycloneDX has no equivalent of SARIF's version control provenance, so repo
        data goes in `metadata.properties`, JSON-encoded.
        """
        metadata = self.content.setdefault("metadata", {})
        metadata["timestamp"] = started_at
        metadata["tools"] = [{"name": "reposcan", "version": reposcan_version}]
        properties = [
            property
            for property in metadata.get("properties", [])
            if not str(property.get("name", "")).startswith("reposcan:")
        ]
        properties.append({"name": _SCHEMA_PROPERTY, "value": str(PROPERTY_SCHEMA)})
        properties.append(
            {
                "name": _REPOSITORY_PROPERTY,
                "value": json.dumps(repository.to_properties()),
            }
        )
        properties.append(
            {
                "name": _ANALYSIS_PROPERTY,
                "value": json.dumps(
                    {
                        "uuid": analysis_uuid,
                        "startedAt": started_at,
                        "finishedAt": finished_at,
                    }
                ),
            }
        )
        metadata["properties"] = properties

    def record_invocations(self, invocations: list[ToolInvocationRecord]) -> None:
        """Record the tool commands that produced this SBOM, replacing any held."""
        self.tool_invocations.clear()
        self.tool_invocations.extend(invocations)


def parse(text: str, scanner: str | None = None) -> CycloneDxDocument | None:
    """The CycloneDX document in `text`, or None if `text` is not CycloneDX.

    Pass `scanner` to annotate every component with the reposcan:scanner property.

    Args:
        text: JSON text expected to be a CycloneDX document.
        scanner: The scanner that produced the SBOM, to annotate its components; None
            to read the document back unchanged.

    Returns:
        A CycloneDxDocument if `text` is a CycloneDX JSON object, else None.
    """
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        return None
    # syft always lists a component named "." (or "./") for the scanned
    # directory, which is the source, not a dependency.
    components = document.get("components")
    if isinstance(components, list):
        document["components"] = [
            component
            for component in components
            if str(component.get("name", "")) not in (".", "./")
        ]
    sbom = CycloneDxDocument(document)
    if scanner is not None:
        for component in sbom.components():
            _record_scanner(component, scanner)
    return sbom


def _component_key(component: dict[str, Any]) -> str:
    """A dedup key for a component: its package URL, else type/name/version."""
    purl = component.get("purl")
    if purl:
        return f"purl:{purl}"
    type_ = component.get("type", "")
    name = component.get("name", "")
    version = component.get("version", "")
    return f"nv:{type_}:{name}:{version}"


def _record_scanner(component: dict[str, Any], scanner: str) -> None:
    """Add `scanner` to the component's properties (no duplicates)."""
    properties = component.setdefault("properties", [])
    for existing in properties:
        if (
            existing.get("name") == SCANNER_PROPERTY
            and existing.get("value") == scanner
        ):
            return
    properties.append({"name": SCANNER_PROPERTY, "value": scanner})


def _serialize_invocation(index: int, inv: ToolInvocationRecord) -> dict[str, Any]:
    """One executed tool command, as a CycloneDX formulation workflow."""
    workflow: dict[str, Any] = {
        "bom-ref": f"reposcan-{inv.tool}-{index}",
        "uid": f"{inv.tool}-{index}",
        "name": f"{inv.tool} {inv.version}",
        "taskTypes": ["scan"],
        "steps": [
            {"name": inv.tool, "commands": [{"executed": shlex.join(inv.command)}]}
        ],
        "properties": [
            {"name": _TOOL_PROPERTY, "value": inv.tool},
            {"name": _VERSION_PROPERTY, "value": inv.version},
            # `commands[].executed` is a display string by spec, so the argv is
            # carried here instead; otherwise it could not be read back exactly.
            {"name": _COMMAND_PROPERTY, "value": json.dumps(list(inv.command))},
            # The argv the scan asked for, before reposcan appended any of its own.
            {"name": _ARGS_PROPERTY, "value": json.dumps(list(inv.args))},
            {"name": _OK_CODES_PROPERTY, "value": json.dumps(list(inv.ok_codes))},
            {"name": _OPTIONAL_PROPERTY, "value": str(inv.optional).lower()},
            # JSON so that "unset" stays distinct from "set to the empty string";
            # CycloneDX property values are strings by spec.
            {"name": _CWD_PROPERTY, "value": json.dumps(inv.cwd)},
            {
                "name": _ENV_PROPERTY,
                "value": json.dumps(None if inv.env is None else dict(inv.env)),
            },
            {"name": _OUTPUT_FILE_PROPERTY, "value": json.dumps(inv.output_file)},
            {"name": _DIRECTORY_PROPERTY, "value": inv.working_directory},
            {"name": _EXIT_CODE_PROPERTY, "value": str(inv.exit_code)},
            {"name": _SUCCESSFUL_PROPERTY, "value": str(inv.successful).lower()},
        ],
    }
    if inv.environment:
        workflow["inputs"] = [
            {
                "environmentVars": [
                    {"name": key, "value": value}
                    for key, value in inv.environment.items()
                ]
            }
        ]
    return workflow


def _deserialize_invocation(workflow: dict[str, Any]) -> ToolInvocationRecord:
    """The record `_serialize_invocation` wrote.

    Only called for workflows under reposcan's own formulation entry, so every
    property it reads is one reposcan wrote. Every field of the record is written and
    read back, so the pair is a true inverse: a document that is serialized and parsed
    again holds the records it started with.
    """
    properties = {
        str(prop.get("name", "")): str(prop.get("value", ""))
        for prop in workflow.get("properties", [])
    }
    return ToolInvocationRecord(
        tool=properties.get(_TOOL_PROPERTY, ""),
        args=json.loads(properties.get(_ARGS_PROPERTY, "[]")),
        ok_codes=tuple(json.loads(properties.get(_OK_CODES_PROPERTY, "[0]"))),
        optional=properties.get(_OPTIONAL_PROPERTY, "") == "true",
        cwd=json.loads(properties.get(_CWD_PROPERTY, "null")),
        env=json.loads(properties.get(_ENV_PROPERTY, "null")),
        output_file=json.loads(properties.get(_OUTPUT_FILE_PROPERTY, "null")),
        version=properties.get(_VERSION_PROPERTY, ""),
        command=tuple(json.loads(properties.get(_COMMAND_PROPERTY, "[]"))),
        working_directory=properties.get(_DIRECTORY_PROPERTY, ""),
        environment={
            str(var.get("name", "")): str(var.get("value", ""))
            for entry in workflow.get("inputs", [])
            for var in entry.get("environmentVars", [])
        },
        exit_code=int(properties.get(_EXIT_CODE_PROPERTY, "-1")),
        successful=properties.get(_SUCCESSFUL_PROPERTY, "") == "true",
    )


def _merge_scanners(into: dict[str, Any], other: dict[str, Any]) -> None:
    """Union `other`'s reposcan:scanner properties into `into` (no duplicates)."""
    for prop in other.get("properties", []):
        if prop.get("name") == SCANNER_PROPERTY:
            _record_scanner(into, str(prop.get("value", "")))


def merge(documents: Sequence[CycloneDxDocument]) -> CycloneDxDocument:
    """Consolidate one or more normalized CycloneDX SBOMs into one deduped SBOM.

    Components with the same package URL (or type/name/version) are deduped.

    Args:
        documents: The normalized CycloneDX artifacts to combine.

    Returns:
        A single CycloneDxDocument (CycloneDX 1.5).
    """
    by_key: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for document in documents:
        for component in document.to_dict().get("components", []):
            key = _component_key(component)
            if key in by_key:
                _merge_scanners(by_key[key], component)
                continue
            copied = copy.deepcopy(component)
            by_key[key] = copied
            order.append(key)
    content: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [by_key[key] for key in order],
    }
    # Carry every input's recorded formulation (tool provenance) onto the merged SBOM.
    formulation = [
        entry
        for document in documents
        for entry in document.to_dict().get("formulation", [])
    ]
    if formulation:
        content["formulation"] = formulation
    return CycloneDxDocument(content)

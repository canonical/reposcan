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
from dataclasses import dataclass
from typing import Any, ClassVar

from repo_scanner.ioutil.sqlitedb import Table
from repo_scanner.scans.model import Artifact, ArtifactKind, ToolInvocationRecord

# The property name carrying each contributing scanner on a merged component.
SCANNER_PROPERTY = "reposcan:scanner"


@dataclass(frozen=True)
class CycloneDxDocument:
    """A CycloneDX SBOM artifact (an Artifact of kind CYCLONEDX).

    Wraps the rendered CycloneDX `content` (a tool's output, or a `merge`).
    """

    kind: ClassVar[ArtifactKind] = ArtifactKind.CYCLONEDX
    content: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """The artifact as a CycloneDX document object."""
        return self.content

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

    def records(self) -> Table:
        """The components as a `components` table for querying and reconstruction.

        Parsed columns (package URL, the merge's contributing scanners from the
        `reposcan:scanner` properties) plus `document` (the component's raw JSON, so a
        single component reconstructs). In document order.
        """
        columns = ("name", "version", "type", "purl", "scanners", "document")
        components = [
            (
                str(component.get("name", "")),
                str(component.get("version", "")),
                str(component.get("type", "")),
                str(component.get("purl", "")),
                ",".join(
                    str(prop.get("value", ""))
                    for prop in component.get("properties", [])
                    if prop.get("name") == SCANNER_PROPERTY
                ),
                json.dumps(component),
            )
            for component in self.components()
        ]
        return Table("components", columns, components)

    def record_invocations(self, invocations: list[ToolInvocationRecord]) -> None:
        """Record each executed tool command in the SBOM's CycloneDX `formulation`.

        Each command is a workflow (a "scan" task) whose step holds the executed
        command line and whose input holds the environment reposcan set.
        """
        if not invocations:
            return
        workflows = [
            _workflow_object(index, inv) for index, inv in enumerate(invocations)
        ]
        self.content.setdefault("formulation", []).append(
            {"bom-ref": "reposcan-scan", "workflows": workflows}
        )


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


def _workflow_object(index: int, inv: ToolInvocationRecord) -> dict[str, Any]:
    """A CycloneDX formulation workflow for one executed tool command."""
    workflow: dict[str, Any] = {
        "bom-ref": f"reposcan-{inv.tool}-{index}",
        "uid": f"{inv.tool}-{index}",
        "name": f"{inv.tool} {inv.version}",
        "taskTypes": ["scan"],
        "steps": [
            {"name": inv.tool, "commands": [{"executed": shlex.join(inv.command)}]}
        ],
        "properties": [
            {"name": "reposcan:workingDirectory", "value": inv.working_directory},
            {"name": "reposcan:exitCode", "value": str(inv.exit_code)},
            {"name": "reposcan:successful", "value": str(inv.successful).lower()},
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


def _merge_scanners(into: dict[str, Any], other: dict[str, Any]) -> None:
    """Union `other`'s reposcan:scanner properties into `into` (no duplicates)."""
    for prop in other.get("properties", []):
        if prop.get("name") == SCANNER_PROPERTY:
            _record_scanner(into, str(prop.get("value", "")))


def merge(documents: Sequence[Artifact]) -> CycloneDxDocument:
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

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Build/parse SARIF 2.1.0 documents from scan findings."""

import copy
import json
import shlex
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, ClassVar

from repo_scanner.ioutil.sqlitedb import Table, TableSchema
from repo_scanner.scans.model import Artifact, ArtifactKind, ToolInvocationRecord

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# db schema for findings table
FINDINGS = TableSchema(
    name="findings",
    columns=("rule", "level", "uri", "line", "message", "scanners", "run", "document"),
    create=(
        "CREATE TABLE findings (rule TEXT, level TEXT, uri TEXT, line TEXT, "
        "message TEXT, scanners TEXT, run TEXT, document TEXT)"
    ),
    insert="INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    select="SELECT * FROM findings ORDER BY rowid",
)

# SARIF severity levels from most to least severe; unlisted levels sort last.
_LEVEL_RANK = {"error": 0, "warning": 1, "note": 2, "none": 3}


@dataclass(frozen=True)
class SarifResult:
    """A SARIF result.

    `build` creates a normalized finding from fields; the plain `SarifResult(dict)`
    constructor is a view over a dict that is already normalized (from `build`, `parse`,
    or a `merge` of those). Normalized results include: a properties.scanners
    annotation, a repository-root-relative uri on every location, and a level.
    """

    result: dict[str, Any]

    @classmethod
    def build(
        cls,
        rule_id: str,
        message: str,
        uri: str,
        start_line: int,
        scanner: str,
        target: str,
        level: str = "warning",
    ) -> "SarifResult":
        """Build a finding from fields.

        Args:
            rule_id: The rule that produced the finding (e.g. the detector name).
            message: A human-readable description of the finding.
            uri: The file the finding is in, as the tool reported it.
            start_line: The 1-indexed line of the finding, or 0 if unknown.
            scanner: The scanner that reported the finding (its properties.scanners).
            target: The scan root, used to make `uri` repository-root-relative.
            level: The SARIF level ("error", "warning", "note").
        """
        physical: dict[str, Any] = {"artifactLocation": {"uri": uri}}
        if start_line:
            physical["region"] = {"startLine": start_line}
        result = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message},
            "locations": [{"physicalLocation": physical}],
        }
        _normalize_result(result, scanner, target)
        return cls(result)

    @property
    def rule_id(self) -> str:
        """The id of the rule that produced the finding."""
        return str(self.result.get("ruleId", ""))

    @property
    def level(self) -> str:
        """The finding's SARIF level, defaulting to "warning"."""
        return str(self.result.get("level") or "warning")

    @property
    def message(self) -> str:
        """The finding's human-readable message text."""
        return str(self.result.get("message", {}).get("text", ""))

    @property
    def uri(self) -> str:
        """The repo-relative file uri of the finding's primary location, or ''."""
        return str(self._physical_location().get("artifactLocation", {}).get("uri", ""))

    @property
    def line(self) -> int:
        """The 1-indexed start line of the finding's primary location, or 0."""
        line = self._physical_location().get("region", {}).get("startLine")
        return line if isinstance(line, int) else 0

    @property
    def location(self) -> str:
        """The 'uri:line' of the primary location, or just the uri when lineless."""
        return f"{self.uri}:{self.line}" if self.line else self.uri

    @property
    def scanners(self) -> list[str]:
        """The scanner(s) that reported the finding, from its normalized annotation."""
        scanners = self.result.get("properties", {}).get("scanners")
        if isinstance(scanners, list) and scanners:
            return [str(scanner) for scanner in scanners]
        return []

    @property
    def key(self) -> tuple[str, str, int]:
        """A dedup key: the finding's rule and primary location."""
        return (self.rule_id, self.uri, self.line)

    def _physical_location(self) -> dict[str, Any]:
        """The primary location's physicalLocation dict, or an empty one."""
        locations = self.result.get("locations") or []
        return locations[0].get("physicalLocation", {}) if locations else {}


@dataclass(frozen=True)
class SarifDocument:
    """A SARIF 2.1.0 document."""

    kind: ClassVar[ArtifactKind] = ArtifactKind.SARIF
    content: dict[str, Any]

    @classmethod
    def from_results(
        cls, scanner: str, version: str, results: list[SarifResult]
    ) -> "SarifDocument":
        """Assemble findings into a document.

        Args:
            scanner: The scanner that produced the findings.
            version: The scanner's version.
            results: The normalized findings the run reports.
        """
        driver = {"name": scanner, "version": version}
        content = {
            "$schema": SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": driver},
                    "results": [finding.result for finding in results],
                }
            ],
        }
        return cls(content)

    def to_dict(self) -> dict[str, Any]:
        """The artifact as a SARIF 2.1.0 document object."""
        return self.content

    def results(self) -> list[SarifResult]:
        """Every finding as a SarifResult, flattened across all runs."""
        return [
            SarifResult(result)
            for run in self.content.get("runs", [])
            for result in run.get("results", [])
        ]

    def count(self) -> int:
        """The number of findings across every run."""
        return len(self.results())

    def rows(self) -> tuple[list[str], list[list[str]]]:
        """A table of findings for presentation, most severe first."""
        headers = ["LEVEL", "TOOL", "RULE", "LOCATION", "MESSAGE"]
        rows = [
            [
                finding.level,
                ", ".join(finding.scanners),
                finding.rule_id,
                finding.location,
                finding.message,
            ]
            for finding in self.results()
        ]
        rows.sort(key=lambda row: _LEVEL_RANK.get(row[0], len(_LEVEL_RANK)))
        return headers, rows

    def records(self) -> Table:
        """The findings as a `FINDINGS` table, for querying and reconstruction.

        Each row splits the location into `uri`/`line`, joins the merge's
        `properties.scanners`, and keeps the result's raw JSON in `document` (so a
        single finding reconstructs) alongside its `run` index.
        """
        findings = []
        for index, run in enumerate(self.content.get("runs", [])):
            for result in run.get("results", []):
                finding = SarifResult(result)
                findings.append(
                    (
                        finding.rule_id,
                        finding.level,
                        finding.uri,
                        str(finding.line) if finding.line else "",
                        finding.message,
                        ",".join(finding.scanners),
                        str(index),
                        json.dumps(result),
                    )
                )
        return Table(FINDINGS, findings)

    def record_invocations(self, invocations: list[ToolInvocationRecord]) -> None:
        """Record each executed tool command under the run's SARIF `invocations`.

        All tools merge into one run, so they share its `invocations` array; each
        tool is identified by its `executableLocation` and a `tool` property.
        """
        runs = self.content.get("runs")
        if not invocations or not runs:
            return
        runs[0]["invocations"] = [_invocation_object(inv) for inv in invocations]


def parse(
    text: str, scanner: str | None = None, target: str = ""
) -> SarifDocument | None:
    """The SARIF document in `text`, or None if `text` is not SARIF.

    Pass `scanner` (and `target`) to normalize a tool's raw output at ingestion; omit
    `scanner` to read an already-normalized report back unchanged.

    Args:
        text: JSON text expected to be a SARIF document.
        scanner: The scanner that produced the SARIF, to normalize its results; None
            to read the document back unchanged.
        target: The scan root, used to make finding uris repository-root-relative
            (only when `scanner` is given).
    """
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not (isinstance(document, dict) and isinstance(document.get("runs"), list)):
        return None
    if scanner is not None:
        _normalize(document, scanner, target)
    return SarifDocument(document)


def merge(documents: Sequence[Artifact]) -> SarifDocument:
    """Consolidate one or more normalized SARIF documents into one "reposcan" doc.

    Results with the same rule and primary location are deduped, their scanner lists
    unioned. The rules referenced by surviving results are carried onto the merged
    driver so their metadata is not lost.

    Args:
        documents: The normalized SARIF artifacts to combine.
    """
    by_key: dict[tuple[str, str, int], dict[str, Any]] = {}
    order: list[tuple[str, str, int]] = []
    rules_by_id: dict[str, dict[str, Any]] = {}
    for document in documents:
        for run in document.to_dict().get("runs", []):
            for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
                rule_id = str(rule.get("id", ""))
                if rule_id and rule_id not in rules_by_id:
                    rules_by_id[rule_id] = rule
            for result in run.get("results", []):
                finding = SarifResult(result)
                key = finding.key
                if key in by_key:
                    for scanner in finding.scanners:
                        _record_scanner(by_key[key], scanner)
                    continue
                copied = copy.deepcopy(result)
                # ruleIndex points into one run's rule list; results also reference
                # rules by id, so drop the now-meaningless index after combining runs.
                copied.pop("ruleIndex", None)
                by_key[key] = copied
                order.append(key)
    results = [by_key[key] for key in order]
    referenced = {str(result.get("ruleId", "")) for result in results}
    rules = [rules_by_id[rule_id] for rule_id in rules_by_id if rule_id in referenced]
    driver: dict[str, Any] = {"name": "reposcan"}
    if rules:
        driver["rules"] = rules
    run: dict[str, Any] = {"tool": {"driver": driver}, "results": results}
    invocations = [
        invocation
        for document in documents
        for source in document.to_dict().get("runs", [])
        for invocation in source.get("invocations", [])
    ]
    if invocations:
        run["invocations"] = invocations
    return SarifDocument({"$schema": SCHEMA, "version": "2.1.0", "runs": [run]})


# --- normalization: turn raw tool results into reposcan's canonical shape ---


def _normalize(document: dict[str, Any], scanner: str, target: str) -> None:
    """Normalize every result in a raw SARIF document, in place (used by `parse`)."""
    for run in document.get("runs", []):
        rule_levels = _rule_levels(run)
        for result in run.get("results", []):
            _normalize_result(result, scanner, target, rule_levels)


def _normalize_result(
    result: dict[str, Any],
    scanner: str,
    target: str,
    rule_levels: dict[str, str] | None = None,
) -> None:
    """Normalize one SARIF result in place.

    Sets an explicit level, records `scanner` in properties.scanners, and relativizes
    every location's uri against `target`.
    """
    if not result.get("level"):
        result["level"] = (rule_levels or {}).get(
            str(result.get("ruleId", "")), "warning"
        )
    _record_scanner(result, scanner)
    for location in result.get("locations") or []:
        artifact = location.get("physicalLocation", {}).get("artifactLocation")
        if isinstance(artifact, dict) and artifact.get("uri"):
            artifact["uri"] = _relative_uri(str(artifact["uri"]), target)


def _rule_levels(run: dict[str, Any]) -> dict[str, str]:
    """Each rule id mapped to its configured level, from a run's tool driver rules."""
    levels: dict[str, str] = {}
    for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
        rule_id = str(rule.get("id", ""))
        level = rule.get("defaultConfiguration", {}).get("level")
        if rule_id and level:
            levels[rule_id] = str(level)
    return levels


def _record_scanner(result: dict[str, Any], scanner: str) -> None:
    """Add `scanner` to the result's properties.scanners list (no duplicates)."""
    scanners = result.setdefault("properties", {}).setdefault("scanners", [])
    if scanner not in scanners:
        scanners.append(scanner)


def _relative_uri(uri: str, target: str) -> str:
    """`uri` made relative to the scan root `target`, matching how git reports paths.

    Drops a `file://` scheme and the `target` prefix; a uri already relative (not
    under `target`) is returned unchanged apart from a leading `./`.
    """
    path = uri.removeprefix("file://")
    root = target.rstrip("/")
    if root and (path == root or path.startswith(root + "/")):
        path = path[len(root) :].lstrip("/")
    return path.removeprefix("./")


# --- rendering ---


def _invocation_object(inv: ToolInvocationRecord) -> dict[str, Any]:
    """A SARIF invocation object for one executed tool command."""
    invocation: dict[str, Any] = {
        "commandLine": shlex.join(inv.command),
        "arguments": list(inv.command[1:]),
        "executableLocation": {"uri": inv.command[0]},
        "workingDirectory": {"uri": inv.working_directory},
        "exitCode": inv.exit_code,
        "executionSuccessful": inv.successful,
        "properties": {"tool": inv.tool, "version": inv.version},
    }
    if inv.environment:
        invocation["environmentVariables"] = dict(inv.environment)
    return invocation

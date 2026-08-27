# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Build/parse SARIF 2.1.0 documents from scan findings."""

import copy
import hashlib
import json
import logging
import shlex
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, ClassVar

from repo_scanner.execution.context import ExecutionContext, read_file
from repo_scanner.scans.model import ArtifactKind, ToolInvocationRecord

logger = logging.getLogger(__name__)

# Namespaced so reposcan's own invocations can be told from another producer's.
_TOOL_PROPERTY = "reposcan:tool"
_VERSION_PROPERTY = "reposcan:version"
_ARGS_PROPERTY = "reposcan:args"
_OK_CODES_PROPERTY = "reposcan:okCodes"
_OPTIONAL_PROPERTY = "reposcan:optional"
_CWD_PROPERTY = "reposcan:cwd"
_ENV_PROPERTY = "reposcan:env"
_OUTPUT_FILE_PROPERTY = "reposcan:outputFile"

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# db schema for findings table
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

    def add_fingerprint(self, name: str, value: str) -> None:
        """Record a complete fingerprint.

        A `fingerprints` entry is a stable identity, fully identifying the finding.
        Not used or recognized by GitHub's code-scanning.
        """
        self.result.setdefault("fingerprints", {})[name] = value

    def _physical_location(self) -> dict[str, Any]:
        """The primary location's physicalLocation dict, or an empty one."""
        locations = self.result.get("locations") or []
        return locations[0].get("physicalLocation", {}) if locations else {}


@dataclass(frozen=True)
class SarifRun:
    """A SARIF run.

    `from_results` builds a run from `SarifResult`s; the plain `SarifRun(dict)`
    constructor is a view over an existing run dict.

    Invocations reposcan recorded are held as `ToolInvocationRecord`s rather than as
    SARIF objects, and `to_dict` renders them back. Constructing a run over a dict
    that already holds them reads them back out into records, so a run that was
    parsed behaves exactly like one that was just produced.
    """

    run: dict[str, Any]
    tool_invocations: list[ToolInvocationRecord] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Read reposcan's own invocations out of the run and into records."""
        kept: list[dict[str, Any]] = []
        for invocation in self.run.get("invocations", []):
            record = _deserialize_invocation(invocation)
            if record is None:
                kept.append(invocation)
            else:
                self.tool_invocations.append(record)
        if "invocations" in self.run:
            self.run["invocations"] = kept

    @classmethod
    def from_results(
        cls, scanner: str, version: str, results: list[SarifResult]
    ) -> "SarifRun":
        """Assemble findings into a run driven by `scanner`.

        Args:
            scanner: The scanner that produced the findings (the run's driver).
            version: The scanner's version.
            results: The normalized findings the run reports.
        """
        driver = {"name": scanner, "version": version}
        return cls(
            {
                "tool": {"driver": driver},
                "results": [finding.result for finding in results],
            }
        )

    def to_dict(self) -> dict[str, Any]:
        """The run as a SARIF run object, with its recorded invocations rendered in."""
        rendered = [_serialize_invocation(inv) for inv in self.tool_invocations]
        invocations = [*self.run.get("invocations", []), *rendered]
        if not invocations:
            return self.run
        return {**self.run, "invocations": invocations}

    def results(self) -> list[SarifResult]:
        """The run's findings, each as a SarifResult."""
        return [SarifResult(result) for result in self.run.get("results", [])]

    @property
    def rules(self) -> list[dict[str, Any]]:
        """The run's tool-driver rule objects (rule metadata), or an empty list."""
        return self.run.get("tool", {}).get("driver", {}).get("rules", [])

    def set_results(self, results: list[SarifResult]) -> None:
        """Replace the run's findings with `results`."""
        self.run["results"] = [finding.result for finding in results]

    def set_automation_id(self, automation_id: str) -> None:
        """Set the run's `automationDetails.id` (its code-scanning category)."""
        self.run["automationDetails"] = {"id": automation_id}

    def record_invocations(self, invocations: list[ToolInvocationRecord]) -> None:
        """Record the tool commands that produced this run, replacing any held."""
        self.tool_invocations.clear()
        self.tool_invocations.extend(invocations)


@dataclass(frozen=True)
class SarifDocument:
    """A SARIF 2.1.0 document."""

    kind: ClassVar[ArtifactKind] = ArtifactKind.SARIF
    content: dict[str, Any]

    @classmethod
    def from_runs(cls, runs: Sequence[SarifRun]) -> "SarifDocument":
        """Assemble runs into a document, keeping each as its own SARIF run.

        Args:
            runs: The runs to report together (e.g. each scan's consolidated run).
        """
        content = {
            "$schema": SCHEMA,
            "version": "2.1.0",
            "runs": [run.to_dict() for run in runs],
        }
        return cls(content)

    def to_dict(self) -> dict[str, Any]:
        """The artifact as a SARIF 2.1.0 document object."""
        return self.content

    def runs(self) -> list[SarifRun]:
        """The document's runs, each as a SarifRun."""
        return [SarifRun(run) for run in self.content.get("runs", [])]

    def results(self) -> list[SarifResult]:
        """Every finding as a SarifResult, flattened across all runs."""
        return [result for run in self.runs() for result in run.results()]

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


def parse_run(text: str, scanner: str, target: str) -> SarifRun | None:
    """Parse one SARIF run from a tool's output."""
    document = parse(text, scanner, target)
    if document is None:
        return None
    runs = document.runs()
    if len(runs) > 1:
        logger.warning("%s produced more than one SARIF run; data may be lost", scanner)
    run = runs[0]
    return run


def merge_runs(runs: Sequence[SarifRun]) -> SarifRun:
    """Merge `SarifRun`s.

    Args:
        runs: The normalized runs to combine (e.g. one scan's per-tool runs).
    """
    by_key: dict[tuple[str, str, int], dict[str, Any]] = {}
    order: list[tuple[str, str, int]] = []
    rules_by_id: dict[str, dict[str, Any]] = {}
    for run in runs:
        for rule in run.rules:
            rule_id = str(rule.get("id", ""))
            if rule_id and rule_id not in rules_by_id:
                rules_by_id[rule_id] = rule
        for finding in run.results():
            key = finding.key
            if key in by_key:
                for scanner in finding.scanners:
                    _record_scanner(by_key[key], scanner)
                continue
            copied = copy.deepcopy(finding.result)
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
    merged: dict[str, Any] = {"tool": {"driver": driver}, "results": results}
    return SarifRun(
        merged,
        [invocation for run in runs for invocation in run.tool_invocations],
    )


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


# --- fingerprinting: give each finding a stable partial fingerprint ---


def add_primarylocationlinehash(
    run: SarifRun, ctx: ExecutionContext, target: str
) -> None:
    """Ensure a primaryLocationLineHash on each run result, in place.

    Applies a stable hash of the primary location's start line, read from the source
    file through `ctx`. Used by GitHub (and others) to de-duplicate.

    The name is deliberately unversioned, against SARIF's `name/vN` convention, because
    GitHub matches code-scanning alerts on this exact property name.

    Identical lines hash identically, so two findings of one rule on two copies of a
    line would be indistinguishable, and a consumer that de-duplicates on the
    fingerprint would treat them as one. Each hash therefore carries the occurrence's
    1-based position among the identical lines of its file, as `<hash>:<n>`, which is
    the form GitHub's own fingerprinting emits.
    """
    # Counted per file, so a line repeated in two files still hashes to ":1" in each.
    occurrences: dict[tuple[str, str], int] = {}
    for finding in run.results():
        if "primaryLocationLineHash" in finding.result.get("partialFingerprints", {}):
            continue
        content = (
            read_file(ctx, finding.uri, cwd=target)
            if finding.uri and finding.line > 0
            else None
        )
        lines = content.splitlines() if content is not None else []
        line = lines[finding.line - 1].strip() if 0 < finding.line <= len(lines) else ""
        if not line:
            logger.warning(
                "could not read the source line for %s:%d; skipping its "
                "primaryLocationLineHash",
                finding.uri or "(no uri)",
                finding.line,
            )
            continue
        digest = hashlib.sha256(line.encode("utf-8", "surrogatepass")).hexdigest()[:16]
        occurrence = occurrences.get((finding.uri, digest), 0) + 1
        occurrences[(finding.uri, digest)] = occurrence
        fingerprints = finding.result.setdefault("partialFingerprints", {})
        fingerprints["primaryLocationLineHash"] = f"{digest}:{occurrence}"


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


def _serialize_invocation(inv: ToolInvocationRecord) -> dict[str, Any]:
    """One executed tool command, as a SARIF invocation object."""
    invocation: dict[str, Any] = {
        "commandLine": shlex.join(inv.command),
        "arguments": list(inv.command[1:]),
        "executableLocation": {"uri": inv.command[0]},
        "workingDirectory": {"uri": inv.working_directory},
        "exitCode": inv.exit_code,
        "executionSuccessful": inv.successful,
        "properties": {
            _TOOL_PROPERTY: inv.tool,
            _VERSION_PROPERTY: inv.version,
            # `arguments` is the whole argv past the executable; these are the ones
            # the scan asked for, before reposcan appended any of its own.
            _ARGS_PROPERTY: list(inv.args),
            _OK_CODES_PROPERTY: list(inv.ok_codes),
            _OPTIONAL_PROPERTY: inv.optional,
            _CWD_PROPERTY: inv.cwd,
            _ENV_PROPERTY: None if inv.env is None else dict(inv.env),
            _OUTPUT_FILE_PROPERTY: inv.output_file,
        },
    }
    if inv.environment:
        invocation["environmentVariables"] = dict(inv.environment)
    return invocation


def _deserialize_invocation(invocation: dict[str, Any]) -> ToolInvocationRecord | None:
    """Deserialize invocations written by `_serialize_invocation`."""
    properties = invocation.get("properties", {})
    if _TOOL_PROPERTY not in properties:
        return None
    executable = invocation.get("executableLocation", {}).get("uri", "")
    return ToolInvocationRecord(
        tool=str(properties[_TOOL_PROPERTY]),
        args=[str(arg) for arg in properties.get(_ARGS_PROPERTY, [])],
        ok_codes=tuple(int(code) for code in properties.get(_OK_CODES_PROPERTY, (0,))),
        optional=bool(properties.get(_OPTIONAL_PROPERTY, False)),
        cwd=properties.get(_CWD_PROPERTY),
        env=properties.get(_ENV_PROPERTY),
        output_file=properties.get(_OUTPUT_FILE_PROPERTY),
        version=str(properties.get(_VERSION_PROPERTY, "")),
        command=(
            str(executable),
            *(str(arg) for arg in invocation.get("arguments", [])),
        ),
        working_directory=str(invocation.get("workingDirectory", {}).get("uri", "")),
        environment=dict(invocation.get("environmentVariables", {})),
        exit_code=int(invocation.get("exitCode", -1)),
        successful=bool(invocation.get("executionSuccessful", False)),
    )

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Write an analysis into the database. Append-only."""

import copy
import json
import logging
from collections.abc import Mapping, Sequence
from typing import Any

from reposcan.db import read, schema, sqlite
from reposcan.db.identity import (
    IssueAttributes,
    derive_component_key,
    is_same_issue,
)
from reposcan.db.model import ImportCounts
from reposcan.db.sqlite import Session, Table
from reposcan.result import Err, Result, is_err
from reposcan.scans import cyclonedx, sarif
from reposcan.scans.analysis import Analysis, ScanOutput, ScanRecord
from reposcan.scans.model import ToolInvocationRecord
from reposcan.scans.repo import ProjectIdentity

logger = logging.getLogger(__name__)


def write_analysis(path: str, record: Analysis) -> Result[None]:
    """Write one analysis into the database at `path`, creating it when absent.

    Resolves the analysis's repository to a project, creating one when nothing
    matches, then appends the analysis and everything under it. An analysis whose uuid
    the database already holds is skipped, so writing the same one twice changes
    nothing.

    Args:
        path: The database file.
        record: The analysis to record.

    Returns:
        None on success, or an Err when `path` is not a reposcan database of this
        version, or cannot be opened.
    """
    if is_err(err := schema.confirm_usable(path)):
        return err
    session = sqlite.connect(path, write=True)
    if isinstance(session, Err):
        return session
    with session:
        schema.create_all(session)
        if session.query(schema.SELECT_ANALYSIS_BY_UUID, (record.uuid,)):
            logger.info("analysis %s is already recorded in %s", record.uuid, path)
            return None
        project_id = resolve_project(session, record.repository.identity)
        analysis_id = insert_analysis(session, record, project_id)
        for scan in record.successful_scans:
            insert_scan(session, analysis_id, project_id, scan)
    return None


def import_database(
    source: str, destination: str, produced_by: str, *, retain_secrets: bool = False
) -> Result[ImportCounts]:
    """Record every analysis of the database at `source` into `destination`.

    Args:
        source: The database to import, which is only ever read.
        destination: The receiving database, created when absent.
        produced_by: Recorded on the analyses `source` left without a producer.
        retain_secrets: Keep the raw secret values that `source`'s findings retained.

    Returns:
        How many analyses were imported and skipped, or an Err when either database
        is unusable or an analysis fails to import.
    """
    if is_err(err := schema.confirm_usable(destination)):
        return err
    known_uuids: set[str] = set()
    if schema.is_current(destination):
        known_uuids = {summary.uuid for summary in read.list_analyses(destination)}
    result = sqlite.connect_read_only(source)
    if isinstance(result, Err):
        return result
    imported = 0
    skipped = 0
    with result as session:
        list_result = _list_importable_analyses(session, source)
        if isinstance(list_result, Err):
            return list_result
        for analysis_id, uuid in list_result:
            if uuid in known_uuids:
                skipped += 1
                continue
            load_result = read.load_analysis(session, analysis_id)
            if isinstance(load_result, Err):
                return Err(
                    f"could not read analysis {uuid} of {source}: {load_result.msg}"
                )
            analysis = load_result
            if not analysis.produced_by:
                analysis.produced_by = produced_by
            # The rows came from elsewhere, and stripping and recording read them again.
            try:
                if not retain_secrets:
                    for run in analysis.sarif_runs:
                        run.remove_secrets()
                err = write_analysis(destination, analysis)
            except read.MALFORMED_ROW_ERRORS as exc:
                return Err(
                    f"could not record analysis {uuid} in {destination}: "
                    f"{type(exc).__name__}: {exc}"
                )
            if is_err(err):
                return err
            logger.debug("imported analysis %s", uuid)
            imported += 1
    return ImportCounts(imported=imported, skipped=skipped)


def _list_importable_analyses(
    session: Session, source: str
) -> Result[list[tuple[int, str]]]:
    """List the id and uuid of every analysis in `source`, oldest-ingested first.

    Returns:
        The list, or an Err when `source` is not a whole reposcan database of this
        version.
    """
    try:
        if session.read_version() != schema.SCHEMA_VERSION:
            return Err(
                f"{source} is not a version {schema.SCHEMA_VERSION} reposcan database"
            )
        # A view standing in for a table could compute rows without end.
        for table in schema.TABLES:
            if not session.has_table(table.name):
                return Err(f"{source} has no {table.name} table")
        return [
            (int(row[0]), str(row[2])) for row in session.query(schema.SELECT_ANALYSES)
        ]
    except read.MALFORMED_ROW_ERRORS as exc:
        hint = ""
        if "readonly" in str(exc):
            hint = (
                "; copy it to a writable directory first, because sqlite creates a "
                "file beside a database to read it"
            )
        return Err(f"could not read {source}: {exc}{hint}")


def resolve_project(session: Session, identity: ProjectIdentity) -> int:
    """Resolve `identity` to a project, creating one when nothing matches.

    Matching follows `ProjectIdentity.matches`, which prefers the strongest signal
    both sides carry. A new project is ordinary rather than an error: a database may
    hold several repositories.
    """
    statement = schema.PROJECT.select
    assert statement is not None
    for row in session.query(statement):
        project_id, name, root_commit, origin, label = row
        candidate = ProjectIdentity(
            str(name), str(root_commit), str(origin), str(label)
        )
        matched, signal = identity.matches(candidate)
        if matched:
            if signal == "name":
                logger.warning(
                    "matching project %r by directory name alone; pass an explicit "
                    "project label if this is a different repository",
                    name,
                )
            return int(project_id)
    logger.info("recording a new project: %s", identity.name)
    return session.insert_row(
        schema.PROJECT.insert,
        (identity.name, identity.root_commit, identity.origin, identity.label),
    )


def insert_analysis(session: Session, record: Analysis, project_id: int) -> int:
    """Insert the analysis row and return its id."""
    state = record.repository
    return session.insert_row(
        schema.ANALYSIS.insert,
        (
            record.uuid,
            record.produced_by,
            project_id,
            record.started_at,
            record.finished_at,
            record.reposcan_version,
            state.identity.name,
            state.branch,
            state.commit_sha,
            int(state.dirty),
            int(state.shallow),
            record.status.value,
        ),
    )


def insert_scan(
    session: Session, analysis_id: int, project_id: int, record: ScanRecord
) -> None:
    """Insert one scan type's row, its invocations, and its reports."""
    produced = record.produced
    scan_id = session.insert_row(
        schema.SCAN.insert,
        (
            analysis_id,
            record.category,
            record.kind.value,
            record.started_at,
            record.finished_at,
            record.status.value,
            json.dumps(get_shell(produced)),
        ),
    )
    session.insert(
        Table(
            schema.INVOCATION,
            _build_invocation_rows(scan_id, produced.tool_invocations),
        )
    )
    tracker = _Tracker(session, project_id, record.category)
    if isinstance(produced, sarif.SarifRun):
        insert_issue_reports(session, scan_id, produced, tracker)
    else:
        session.insert(
            Table(
                schema.COMPONENT_REPORT,
                _build_component_report_rows(scan_id, produced, tracker),
            )
        )


def get_shell(produced: ScanOutput) -> dict[str, Any]:
    """Return the scan's document without results or components."""
    shell = copy.deepcopy(produced.to_dict())
    if isinstance(produced, sarif.SarifRun):
        shell["results"] = []
    else:
        shell["components"] = []
    return shell


class _Tracker:
    """Resolves what a scan reported to the durable issue or component it is about.

    In other words: each scan reports point-in-time results, and two consecutive scans
    report the same underlying issue. This resolves one report to the issue (or
    component) already tracked, adding it when it is not.

    Issues and components are recognised differently, because a component has a real
    identifier (package url) and an issue does not. Each incoming report is compared
    against every known issue, looking for sufficient evidence that the two are the
    same issue.

    A record is created on its first report and reused on every subsequent report.
    """

    def __init__(self, session: Session, project_id: int, category: str) -> None:
        self.session = session
        self.project_id = project_id
        self.category = category

    def resolve_component(self, component: Mapping[str, Any]) -> int:
        """Resolve the component to an id, creating it if new.

        Keyed on the normalized package url, which identifies a package outright, so
        there is nothing for candidate matching to add.
        """
        component_key = derive_component_key(component)
        rows = self.session.query(
            schema.SELECT_COMPONENT_ID, (self.project_id, component_key)
        )
        if rows:
            return int(rows[0][0])
        return self.session.insert_row(
            schema.COMPONENT.insert, (self.project_id, component_key)
        )

    def resolve_issue(self, finding: sarif.SarifResult) -> int:
        """Resolve the finding to an issue id, creating it if new."""
        incoming = IssueAttributes.from_result(finding)
        for issue_id, known in self._find_candidates(incoming.rule):
            if is_same_issue(known, incoming, self.category):
                self._remember(issue_id, incoming)
                return issue_id
        issue_id = self.session.insert_row(
            schema.ISSUE.insert, (self.project_id, self.category, incoming.rule)
        )
        self._remember(issue_id, incoming)
        return issue_id

    def _find_candidates(self, rule: str) -> list[tuple[int, IssueAttributes]]:
        """Collect every recorded issue of this scan type with the same `rule`.

        A row per fingerprint, so they are gathered back onto one set of attributes
        per issue.
        """
        located: dict[int, IssueAttributes] = {}
        for issue_id, uri, line, complete, name, value in self.session.query(
            schema.SELECT_CANDIDATES, (self.project_id, self.category, rule)
        ):
            attributes = located.setdefault(
                int(issue_id),
                IssueAttributes(rule=rule, uri=str(uri), line=str(line)),
            )
            if name is not None:
                names = (
                    attributes.fingerprints
                    if complete
                    else (attributes.partial_fingerprints)
                )
                names[str(name)] = str(value)
        return list(located.items())

    def _remember(self, issue_id: int, attributes: IssueAttributes) -> None:
        """Record the fingerprints this report carried."""
        for name, value in attributes.fingerprints.items():
            self.session.execute(
                schema.UPSERT_ISSUE_FINGERPRINT, (issue_id, 1, name, value)
            )
        for name, value in attributes.partial_fingerprints.items():
            self.session.execute(
                schema.UPSERT_ISSUE_FINGERPRINT, (issue_id, 0, name, value)
            )


def insert_issue_reports(
    session: Session, scan_id: int, run: sarif.SarifRun, tracker: "_Tracker"
) -> None:
    """Insert one row per result, in the order the scan reported them.

    Written one at a time rather than as a batch, because resolving a report looks up
    the issues already recorded: an issue minted for the first report of a scan has to
    be visible to the rest of it.

    `result_index` is a result's place in the scan's results. Fingerprints are pulled
    out of the result and stored as JSON columns.
    """
    for result_index, result in enumerate(run.to_dict().get("results", [])):
        finding = sarif.SarifResult(result)
        session.execute(
            schema.ISSUE_REPORT.insert,
            (
                scan_id,
                tracker.resolve_issue(finding),
                result_index,
                finding.level,
                finding.uri,
                str(finding.line) if finding.line else "",
                finding.message,
                ",".join(finding.scanners),
                json.dumps(result.get("fingerprints", {})),
                json.dumps(result.get("partialFingerprints", {})),
                json.dumps(result),
            ),
        )


def _build_component_report_rows(
    scan_id: int, document: cyclonedx.CycloneDxDocument, tracker: "_Tracker"
) -> list[tuple[object, ...]]:
    """Build one row per component, addressed by its index in the inventory."""
    return [
        (
            scan_id,
            tracker.resolve_component(component),
            component_index,
            str(component.get("name", "")),
            str(component.get("version", "")),
            str(component.get("type", "")),
            str(component.get("purl", "")),
            ",".join(
                str(prop.get("value", ""))
                for prop in component.get("properties", [])
                if prop.get("name") == cyclonedx.SCANNER_PROPERTY
            ),
            json.dumps(component),
        )
        for component_index, component in enumerate(
            document.to_dict().get("components", []) or []
        )
    ]


def _build_invocation_rows(
    scan_id: int, invocations: Sequence[ToolInvocationRecord]
) -> list[tuple[object, ...]]:
    """Build one row per executed tool command, in the order they ran in."""
    return [
        (
            scan_id,
            command_index,
            inv.tool,
            inv.version,
            json.dumps(list(inv.command)),
            inv.working_directory,
            json.dumps(dict(inv.environment)),
            inv.exit_code,
            int(inv.successful),
        )
        for command_index, inv in enumerate(invocations)
    ]

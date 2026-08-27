# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Write an analysis into the database. Append-only."""

import copy
import json
import logging
from collections.abc import Mapping, Sequence
from typing import Any

from repo_scanner.db import schema
from repo_scanner.db.identity import (
    IssueAttributes,
    derive_component_key,
    same_issue,
)
from repo_scanner.db.model import AnalysisRecord, ScanRecord
from repo_scanner.execution.process import Failure
from repo_scanner.ioutil import sqlitedb
from repo_scanner.ioutil.sqlitedb import Session, Table
from repo_scanner.scans import cyclonedx, sarif
from repo_scanner.scans.model import ToolInvocationRecord
from repo_scanner.scans.repo import ProjectIdentity

logger = logging.getLogger(__name__)


def analysis(
    path: str, record: AnalysisRecord, scans: Sequence[ScanRecord]
) -> Failure | None:
    """Ingest one analysis into the database at `path`, creating it when absent.

    Resolves the analysis's repository to a project, creating one when nothing
    matches, then appends the analysis and everything under it. An analysis whose uuid
    the database already holds is skipped, so ingesting the same one twice changes
    nothing.

    Args:
        path: The database file.
        record: The invocation being recorded.
        scans: What each scan type produced, in the order they ran.

    Returns:
        None on success, or a Failure when `path` is not a reposcan database of this
        version, or cannot be opened.
    """
    refusal = schema.unusable(path)
    if refusal is not None:
        return Failure(reason=refusal)
    session, error = sqlitedb.connect(path)
    if session is None:
        return Failure(reason=error or f"could not open {path}")
    with session:
        schema.create_all(session)
        if session.query(schema.SELECT_ANALYSIS_BY_UUID, (record.uuid,)):
            logger.info("analysis %s is already recorded in %s", record.uuid, path)
            return None
        project_id = resolve_project(session, record.repository.identity)
        analysis_id = insert_analysis(session, record, project_id)
        for scan in scans:
            insert_scan(session, analysis_id, project_id, scan)
    return None


def resolve_project(session: Session, identity: ProjectIdentity) -> int:
    """The project `identity` names, created when nothing in the database matches.

    Matching follows `ProjectIdentity.matches`, which prefers the strongest signal
    both sides carry. A new project is ordinary rather than an error: a database may
    hold several repositories.
    """
    for row in session.query(schema.SELECT_PROJECTS):
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


def insert_analysis(session: Session, record: AnalysisRecord, project_id: int) -> int:
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
    scan_id = session.insert_row(
        schema.SCAN.insert,
        (
            analysis_id,
            record.category,
            record.kind.value,
            record.started_at,
            record.finished_at,
            record.status.value,
            json.dumps(get_shell(record)),
        ),
    )
    session.insert(
        Table(schema.INVOCATION, _invocation_rows(scan_id, record.invocations))
    )
    tracker = _Tracker(session, project_id, record.category)
    if isinstance(record.produced, sarif.SarifRun):
        insert_issue_reports(session, scan_id, record.produced, tracker)
    else:
        session.insert(
            Table(
                schema.COMPONENT_REPORT,
                _component_report_rows(scan_id, record.produced, tracker),
            )
        )


def get_shell(record: ScanRecord) -> dict[str, Any]:
    """What the scan produced, with its entries and its invocations emptied."""
    shell = copy.deepcopy(record.produced.to_dict())
    if isinstance(record.produced, sarif.SarifRun):
        shell["results"] = []
        shell.pop("invocations", None)
    else:
        shell["components"] = []
        shell.pop("formulation", None)
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
        """The id of the component this reports, created if it is new.

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
        """The id of the issue this report is about, created if it is new."""
        incoming = IssueAttributes.from_result(finding)
        for issue_id, known in self._candidates(incoming.rule):
            if same_issue(known, incoming, self.category):
                self._remember(issue_id, incoming)
                return issue_id
        issue_id = self.session.insert_row(
            schema.ISSUE.insert, (self.project_id, self.category, incoming.rule)
        )
        self._remember(issue_id, incoming)
        return issue_id

    def _candidates(self, rule: str) -> list[tuple[int, IssueAttributes]]:
        """Every issue of this scan type that `rule` found, and what is known of it.

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


def _component_report_rows(
    scan_id: int, document: cyclonedx.CycloneDxDocument, tracker: "_Tracker"
) -> list[tuple[object, ...]]:
    """One row per component, addressed by its index in the inventory."""
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


def _invocation_rows(
    scan_id: int, invocations: Sequence[ToolInvocationRecord]
) -> list[tuple[object, ...]]:
    """One row per executed tool command, indexed by the order they ran in."""
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

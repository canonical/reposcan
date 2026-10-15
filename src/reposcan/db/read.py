# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Read the database."""

import json
import logging
import sqlite3
from typing import Any

from reposcan.db import schema, sqlite
from reposcan.db.model import (
    AnalysisSummary,
    Component,
    ComponentVersion,
    Issue,
    ProjectSummary,
)
from reposcan.result import Err, Result
from reposcan.scans import cyclonedx, sarif
from reposcan.scans.analysis import Analysis, ScanOutput, ScanRecord, ScanStatus
from reposcan.scans.model import Artifact, ArtifactKind
from reposcan.scans.repo import ProjectIdentity, RepositoryState

logger = logging.getLogger(__name__)

MALFORMED_ROW_ERRORS = (
    sqlite3.Error,
    ValueError,
    KeyError,
    TypeError,
    AttributeError,
    RecursionError,
)


def list_artifacts(
    path: str, analysis_id: int | None = None, *, project_id: int | None = None
) -> list[Artifact]:
    """Retrieve the artifacts from one analysis.

    Args:
        path: The database file.
        analysis_id: The analysis to read, or None for the most recent one.
        project_id: Which repository's most recent analysis to take, when the database
            holds several and `analysis_id` is None.

    Returns:
        The analysis's findings as one SARIF document holding a run per scan type, and
        its SBOM as a CycloneDX document, in the order they ran. Empty when `path` is
        not a reposcan database of this version, or holds no such analysis.
    """
    session = _open_session(path)
    if session is None:
        return []
    runs: list[sarif.SarifRun] = []
    inventories: list[Artifact] = []
    with session:
        chosen = _choose_analysis(session, analysis_id, project_id)
        if chosen is None:
            return []
        for scan_id, category, artifact_kind, artifact_shell in session.query(
            schema.SELECT_SCANS_FOR_ANALYSIS, (chosen,)
        ):
            shell = json.loads(str(artifact_shell))
            if str(artifact_kind) == ArtifactKind.SARIF.value:
                runs.append(_rebuild_run(session, int(scan_id), shell))
            else:
                inventories.append(_rebuild_cyclonedx(session, int(scan_id), shell))
            logger.debug("read %s scan from analysis %s", category, chosen)
    # The scan types share one document, exactly as the analysis emitted them: each is
    # a run of its own, told apart by its automation id.
    findings = [sarif.SarifDocument.from_runs(runs)] if runs else []
    return findings + inventories


def list_projects(path: str) -> list[ProjectSummary]:
    """List every repository the database holds, oldest first."""
    session = _open_session(path)
    if session is None:
        return []
    statement = schema.PROJECT.select
    assert statement is not None
    with session:
        return [
            ProjectSummary(
                int(project_id),
                str(name),
                str(root_commit),
                str(origin),
                str(label),
            )
            for project_id, name, root_commit, origin, label in session.query(statement)
        ]


def list_issues(path: str, project_id: int) -> list[Issue]:
    """List every issue ever identified in a repository, oldest first."""
    session = _open_session(path)
    if session is None:
        return []
    with session:
        return [
            Issue(
                issue_id=int(issue_id),
                project_id=int(project),
                category=str(category),
                rule=str(rule),
                first_seen_analysis=int(first_seen),
                last_seen_analysis=int(last_seen),
            )
            for issue_id, project, category, rule, first_seen, last_seen in (
                session.query(schema.SELECT_ISSUES, (project_id,))
            )
        ]


def list_components(path: str, project_id: int) -> list[Component]:
    """List every component ever identified in a repository, oldest first."""
    session = _open_session(path)
    if session is None:
        return []
    with session:
        return [
            Component(
                component_id=int(component_id),
                project_id=int(project),
                component_key=str(component_key),
                first_seen_analysis=int(first_seen),
                last_seen_analysis=int(last_seen),
            )
            for component_id, project, component_key, first_seen, last_seen in (
                session.query(schema.SELECT_COMPONENTS, (project_id,))
            )
        ]


def list_versions(path: str, component_id: int) -> list[ComponentVersion]:
    """List every version a component has been reported at, oldest first.

    A span runs from the earliest analysis that saw the version to the latest, so a
    version used, dropped, and later rolled back to is one span covering the gap.
    """
    session = _open_session(path)
    if session is None:
        return []
    with session:
        return [
            ComponentVersion(
                version=str(version),
                first_seen_analysis=int(first_seen),
                last_seen_analysis=int(last_seen),
                analysis_count=int(count),
            )
            for version, first_seen, last_seen, count in session.query(
                schema.SELECT_COMPONENT_VERSIONS, (component_id,)
            )
        ]


def list_analyses(path: str) -> list[AnalysisSummary]:
    """List every analysis the database holds, in the order it was ingested."""
    session = _open_session(path)
    if session is None:
        return []
    with session:
        summaries = []
        for row in session.query(schema.SELECT_ANALYSES):
            analysis_id = int(row[0])
            categories = tuple(
                str(category)
                for (category,) in session.query(
                    schema.SELECT_CATEGORIES_FOR_ANALYSIS, (analysis_id,)
                )
            )
            summaries.append(
                AnalysisSummary(
                    analysis_id=analysis_id,
                    project_id=int(row[1]),
                    uuid=str(row[2]),
                    started_at=str(row[3]),
                    status=ScanStatus(str(row[4])),
                    produced_by=str(row[5]),
                    commit_sha=str(row[6]),
                    branch=str(row[7]),
                    dirty=bool(row[8]),
                    shallow=bool(row[9]),
                    categories=categories,
                )
            )
        return summaries


def load_analysis(session: sqlite.Session, analysis_id: int) -> Result[Analysis]:
    """Rebuild one recorded analysis, with its scans, ready to record elsewhere.

    Returns:
        The analysis, or an Err when it is missing or one of its rows does not parse.
    """
    try:
        rows = session.query(schema.SELECT_ANALYSIS_WITH_PROJECT, (analysis_id,))
        if not rows:
            return Err(f"analysis {analysis_id} or its project is missing")
        (
            uuid,
            produced_by,
            started_at,
            finished_at,
            reposcan_version,
            target_name,
            branch,
            commit_sha,
            dirty,
            shallow,
            status,
            root_commit,
            origin,
            label,
        ) = rows[0]
        analysis = Analysis(
            uuid=str(uuid),
            started_at=str(started_at),
            reposcan_version=str(reposcan_version),
            repository=RepositoryState(
                identity=ProjectIdentity(
                    str(target_name), str(root_commit), str(origin), str(label)
                ),
                commit_sha=str(commit_sha),
                branch=str(branch),
                dirty=bool(dirty),
                shallow=bool(shallow),
            ),
            finished_at=str(finished_at),
            produced_by=str(produced_by),
            status=ScanStatus(str(status)),
        )
        for (
            scan_id,
            category,
            artifact_kind,
            scan_started_at,
            scan_finished_at,
            scan_status,
            artifact_shell,
        ) in session.query(schema.SELECT_SCAN_RECORDS_FOR_ANALYSIS, (analysis_id,)):
            kind = ArtifactKind(str(artifact_kind))
            shell = json.loads(str(artifact_shell))
            if kind == ArtifactKind.SARIF:
                produced: ScanOutput = _rebuild_run(session, int(scan_id), shell)
            else:
                produced = _rebuild_cyclonedx(session, int(scan_id), shell)
            analysis.add(
                ScanRecord(
                    category=str(category),
                    kind=kind,
                    started_at=str(scan_started_at),
                    finished_at=str(scan_finished_at),
                    status=ScanStatus(str(scan_status)),
                    produced=produced,
                )
            )
    except MALFORMED_ROW_ERRORS as exc:
        return Err(f"analysis {analysis_id}: {type(exc).__name__}: {exc}")
    return analysis


def _open_session(path: str) -> sqlite.Session | None:
    """Open a session on `path`.

    Returns:
        A session on the database, or None when `path` is not a reposcan database of
        the version this reposcan reads, or cannot be opened. The reason is logged.
    """
    version = sqlite.read_version(path)
    if version is None:
        logger.warning("%s is not a reposcan database", path)
        return None
    if version != schema.SCHEMA_VERSION:
        logger.warning(
            "%s is a version %d reposcan database; this reposcan reads version %d",
            path,
            version,
            schema.SCHEMA_VERSION,
        )
        return None
    opened = sqlite.connect(path)
    if isinstance(opened, Err):
        logger.warning("%s", opened.msg)
        return None
    return opened


def _choose_analysis(
    session: sqlite.Session, analysis_id: int | None, project_id: int | None
) -> int | None:
    """Select an analysis to read."""
    if analysis_id is not None:
        return analysis_id
    if project_id is not None:
        rows = session.query(schema.SELECT_LATEST_ANALYSIS_FOR_PROJECT, (project_id,))
    else:
        rows = session.query(schema.SELECT_LATEST_ANALYSIS)
    return int(rows[0][0]) if rows else None


def _rebuild_run(
    session: sqlite.Session, scan_id: int, shell: dict[str, Any]
) -> sarif.SarifRun:
    """Splice a scan's results back into its emptied run.

    The invocations need no splicing: the shell is the document the scan produced, so
    constructing a run over it reads them back into records. The invocation table is a
    projection of those for querying.
    """
    statement = schema.ISSUE_REPORT.select
    assert statement is not None
    for (result_json,) in session.query(statement, (scan_id,)):
        shell["results"].append(json.loads(str(result_json)))
    return sarif.SarifRun(shell)


def _rebuild_cyclonedx(
    session: sqlite.Session, scan_id: int, shell: dict[str, Any]
) -> cyclonedx.CycloneDxDocument:
    """Splice a scan's components back into its emptied document."""
    statement = schema.COMPONENT_REPORT.select
    assert statement is not None
    shell["components"] = [
        json.loads(str(component_json))
        for (component_json,) in session.query(statement, (scan_id,))
    ]
    return cyclonedx.CycloneDxDocument(shell)

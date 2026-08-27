# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Read the database."""

import json
import logging
from typing import Any

from repo_scanner.db import schema
from repo_scanner.db.model import (
    AnalysisSummary,
    Component,
    Issue,
    ProjectSummary,
    ScanStatus,
)
from repo_scanner.ioutil import sqlitedb
from repo_scanner.scans import cyclonedx, sarif
from repo_scanner.scans.model import Artifact, ArtifactKind, ToolInvocationRecord

logger = logging.getLogger(__name__)


def artifacts(
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
    session = _session(path)
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
            invocations = _read_invocations(session, int(scan_id))
            if str(artifact_kind) == ArtifactKind.SARIF.value:
                runs.append(_rebuild_run(session, int(scan_id), shell, invocations))
            else:
                inventories.append(
                    _rebuild_cyclonedx(session, int(scan_id), shell, invocations)
                )
            logger.debug("read %s scan from analysis %s", category, chosen)
    # The scan types share one document, exactly as the analysis emitted them: each is
    # a run of its own, told apart by its automation id.
    findings = [sarif.SarifDocument.from_runs(runs)] if runs else []
    return findings + inventories


def projects(path: str) -> list[ProjectSummary]:
    """Every repository the database holds, oldest first."""
    session = _session(path)
    if session is None:
        return []
    with session:
        return [
            ProjectSummary(
                int(project_id),
                str(name),
                str(root_commit),
                str(origin),
                str(label),
            )
            for project_id, name, root_commit, origin, label in session.query(
                schema.SELECT_PROJECTS
            )
        ]


def issues(path: str, project_id: int) -> list[Issue]:
    """Every issue ever identified in a repository, oldest first."""
    session = _session(path)
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


def components(path: str, project_id: int) -> list[Component]:
    """Every component ever identified in a repository, oldest first."""
    session = _session(path)
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


def analyses(path: str) -> list[AnalysisSummary]:
    """Every analysis the database holds, in the order it was ingested."""
    session = _session(path)
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


def _session(path: str) -> sqlitedb.Session | None:
    """A session on `path`, or None when it is not a database we can read."""
    if not schema.is_current(path):
        return None
    session, error = sqlitedb.connect(path)
    if session is None:
        logger.warning("%s", error)
    return session


def _choose_analysis(
    session: sqlitedb.Session, analysis_id: int | None, project_id: int | None
) -> int | None:
    """The analysis to read: the one asked for, else the most recent available."""
    if analysis_id is not None:
        return analysis_id
    if project_id is not None:
        rows = session.query(schema.SELECT_LATEST_ANALYSIS_FOR_PROJECT, (project_id,))
    else:
        rows = session.query(schema.SELECT_LATEST_ANALYSIS)
    return int(rows[0][0]) if rows else None


def _rebuild_run(
    session: sqlitedb.Session,
    scan_id: int,
    shell: dict[str, Any],
    invocations: list[ToolInvocationRecord],
) -> sarif.SarifRun:
    """Splice a scan's results and invocations back into its emptied run."""
    for (result_json,) in session.query(schema.ISSUE_REPORT.select, (scan_id,)):
        shell["results"].append(json.loads(str(result_json)))
    rebuilt = sarif.SarifRun(shell)
    rebuilt.record_invocations(invocations)
    return rebuilt


def _rebuild_cyclonedx(
    session: sqlitedb.Session,
    scan_id: int,
    shell: dict[str, Any],
    invocations: list[ToolInvocationRecord],
) -> cyclonedx.CycloneDxDocument:
    """Splice a scan's components and invocations back into its emptied document."""
    shell["components"] = [
        json.loads(str(component_json))
        for (component_json,) in session.query(
            schema.COMPONENT_REPORT.select, (scan_id,)
        )
    ]
    rebuilt = cyclonedx.CycloneDxDocument(shell)
    rebuilt.record_invocations(invocations)
    return rebuilt


def _read_invocations(
    session: sqlitedb.Session, scan_id: int
) -> list[ToolInvocationRecord]:
    """The tool commands a scan executed, in the order they ran."""
    return [
        ToolInvocationRecord(
            tool=str(tool),
            args=[],
            version=str(version),
            command=tuple(json.loads(str(command))),
            working_directory=str(working_directory),
            environment=json.loads(str(environment)),
            exit_code=int(exit_code),
            successful=bool(successful),
        )
        for (
            tool,
            version,
            command,
            working_directory,
            environment,
            exit_code,
            successful,
        ) in session.query(schema.INVOCATION.select, (scan_id,))
    ]

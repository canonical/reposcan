# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Read a report database."""

import json
import logging
from typing import Any

from repo_scanner.db import schema
from repo_scanner.db.model import ProjectSummary, RunStatus, ScanSummary
from repo_scanner.ioutil import sqlitedb
from repo_scanner.scans import cyclonedx, sarif
from repo_scanner.scans.model import Artifact, ArtifactKind, ToolInvocationRecord

logger = logging.getLogger(__name__)


def artifacts(
    path: str, scan_id: int | None = None, *, project_id: int | None = None
) -> list[Artifact]:
    """Retrieve the artifacts from one scan.

    Args:
        path: The database file.
        scan_id: The scan to read, or None for the most recent one.
        project_id: Which repository's most recent scan to take, when the database
            holds several and `scan_id` is None.

    Returns:
        The scan's findings as one SARIF document holding a run per scan type, and its
        SBOM as a CycloneDX document, in the order they ran. Empty when `path` is not a
        reposcan database of this version, or holds no such scan.
    """
    session = _session(path)
    if session is None:
        return []
    runs: list[sarif.SarifRun] = []
    inventories: list[Artifact] = []
    with session:
        chosen = _choose_scan(session, scan_id, project_id)
        if chosen is None:
            return []
        for run_id, category, artifact_kind, artifact_shell in session.query(
            schema.SELECT_RUNS_FOR_SCAN, (chosen,)
        ):
            shell = json.loads(str(artifact_shell))
            invocations = _read_invocations(session, int(run_id))
            if str(artifact_kind) == ArtifactKind.SARIF.value:
                runs.append(_rebuild_run(session, int(run_id), shell, invocations))
            else:
                inventories.append(
                    _rebuild_cyclonedx(session, int(run_id), shell, invocations)
                )
            logger.debug("read %s run from scan %s", category, chosen)
    # The scan types share one document, exactly as the scan emitted them: each is a
    # run of its own, told apart by its automation id.
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


def scans(path: str) -> list[ScanSummary]:
    """Every scan the database holds, in the order it was ingested."""
    session = _session(path)
    if session is None:
        return []
    with session:
        summaries = []
        for row in session.query(schema.SELECT_SCANS):
            scan_id = int(row[0])
            categories = tuple(
                str(category)
                for (category,) in session.query(
                    schema.SELECT_CATEGORIES_FOR_SCAN, (scan_id,)
                )
            )
            summaries.append(
                ScanSummary(
                    scan_id=scan_id,
                    project_id=int(row[1]),
                    uuid=str(row[2]),
                    started_at=str(row[3]),
                    status=RunStatus(str(row[4])),
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
    """A session on `path`, or None when it is not a report database we can read."""
    if not schema.is_current(path):
        return None
    session, error = sqlitedb.connect(path)
    if session is None:
        logger.warning("%s", error)
    return session


def _choose_scan(
    session: sqlitedb.Session, scan_id: int | None, project_id: int | None
) -> int | None:
    """The scan to read: the one asked for, else the most recent one available."""
    if scan_id is not None:
        return scan_id
    if project_id is not None:
        rows = session.query(schema.SELECT_LATEST_SCAN_FOR_PROJECT, (project_id,))
    else:
        rows = session.query(schema.SELECT_LATEST_SCAN)
    return int(rows[0][0]) if rows else None


def _rebuild_run(
    session: sqlitedb.Session,
    run_id: int,
    shell: dict[str, Any],
    invocations: list[ToolInvocationRecord],
) -> sarif.SarifRun:
    """Splice a run's findings and invocations back into its emptied run."""
    for (result_json,) in session.query(schema.FINDINGS.select, (run_id,)):
        shell["results"].append(json.loads(str(result_json)))
    rebuilt = sarif.SarifRun(shell)
    rebuilt.record_invocations(invocations)
    return rebuilt


def _rebuild_cyclonedx(
    session: sqlitedb.Session,
    run_id: int,
    shell: dict[str, Any],
    invocations: list[ToolInvocationRecord],
) -> cyclonedx.CycloneDxDocument:
    """Splice a run's components and invocations back into its emptied document."""
    shell["components"] = [
        json.loads(str(component_json))
        for (component_json,) in session.query(schema.COMPONENTS.select, (run_id,))
    ]
    rebuilt = cyclonedx.CycloneDxDocument(shell)
    rebuilt.record_invocations(invocations)
    return rebuilt


def _read_invocations(
    session: sqlitedb.Session, run_id: int
) -> list[ToolInvocationRecord]:
    """The tool commands a run executed, in the order they ran."""
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
        ) in session.query(schema.INVOCATION.select, (run_id,))
    ]

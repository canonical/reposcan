# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Write a scan into the report database. Append-only."""

import copy
import json
import logging
from collections.abc import Sequence
from typing import Any

from repo_scanner.db import schema
from repo_scanner.db.model import RunRecord, ScanRecord
from repo_scanner.execution.process import Failure
from repo_scanner.ioutil import sqlitedb
from repo_scanner.ioutil.sqlitedb import Session, Table
from repo_scanner.scans import cyclonedx, sarif
from repo_scanner.scans.model import ToolInvocationRecord
from repo_scanner.scans.repo import ProjectIdentity

logger = logging.getLogger(__name__)


def scan(path: str, record: ScanRecord, runs: Sequence[RunRecord]) -> Failure | None:
    """Ingest one scan into the report database at `path`, creating it when absent.

    Resolves the scan's repository to a project, creating one when nothing matches,
    then appends the scan and everything under it. A scan whose uuid the database
    already holds is skipped, so ingesting the same scan twice changes nothing.

    Args:
        path: The database file.
        record: The invocation being recorded.
        runs: What each scan type produced, in the order they ran.

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
        if session.query(schema.SELECT_SCAN_BY_UUID, (record.uuid,)):
            logger.info("scan %s is already recorded in %s", record.uuid, path)
            return None
        project_id = resolve_project(session, record.repository.identity)
        scan_id = insert_scan(session, record, project_id)
        for run in runs:
            insert_run(session, scan_id, run)
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


def insert_scan(session: Session, scan: ScanRecord, project_id: int) -> int:
    """Insert the scan row and return its id."""
    state = scan.repository
    return session.insert_row(
        schema.SCAN.insert,
        (
            scan.uuid,
            scan.produced_by,
            project_id,
            scan.started_at,
            scan.finished_at,
            scan.reposcan_version,
            state.identity.name,
            state.branch,
            state.commit_sha,
            int(state.dirty),
            int(state.shallow),
            scan.status.value,
        ),
    )


def insert_run(session: Session, scan_id: int, record: RunRecord) -> None:
    """Insert one scan type's run, its invocations, and its entries."""
    run_id = session.insert_row(
        schema.RUN.insert,
        (
            scan_id,
            record.category,
            record.kind.value,
            record.started_at,
            record.finished_at,
            record.status.value,
            json.dumps(get_shell(record)),
        ),
    )
    session.insert(
        Table(schema.INVOCATION, _invocation_rows(run_id, record.invocations))
    )
    if isinstance(record.produced, sarif.SarifRun):
        session.insert(
            Table(schema.FINDINGS, build_finding_rows(run_id, record.produced))
        )
    else:
        session.insert(
            Table(schema.COMPONENTS, _component_rows(run_id, record.produced))
        )


def get_shell(record: RunRecord) -> dict[str, Any]:
    """What the run produced, with its entries and its invocations emptied."""
    shell = copy.deepcopy(record.produced.to_dict())
    if isinstance(record.produced, sarif.SarifRun):
        shell["results"] = []
        shell.pop("invocations", None)
    else:
        shell["components"] = []
        shell.pop("formulation", None)
    return shell


def build_finding_rows(run_id: int, run: sarif.SarifRun) -> list[tuple[object, ...]]:
    """One row per finding, in the order the run reported them.

    `result_index` is a finding's place in the run's results, which is what puts it
    back where it came from. Fingerprints are pulled out of the result and stored as
    JSON columns, since they are what identity is derived from.
    """
    rows: list[tuple[object, ...]] = []
    for result_index, result in enumerate(run.to_dict().get("results", [])):
        finding = sarif.SarifResult(result)
        rows.append(
            (
                run_id,
                result_index,
                finding.rule_id,
                finding.level,
                finding.uri,
                str(finding.line) if finding.line else "",
                finding.message,
                ",".join(finding.scanners),
                json.dumps(result.get("fingerprints", {})),
                json.dumps(result.get("partialFingerprints", {})),
                json.dumps(result),
            )
        )
    return rows


def _component_rows(
    run_id: int, document: cyclonedx.CycloneDxDocument
) -> list[tuple[object, ...]]:
    """One row per component, addressed by its index in the inventory."""
    return [
        (
            run_id,
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
    run_id: int, invocations: Sequence[ToolInvocationRecord]
) -> list[tuple[object, ...]]:
    """One row per executed tool command, indexed by the order they ran in."""
    return [
        (
            run_id,
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

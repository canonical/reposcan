# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Store and reconstruct a scan artifact as a sqlite report database.

This is the domain glue between an `Artifact` and the generic tabular store
(`repo_scanner.ioutil.sqlitedb`). The database is normalized so the artifact is both
queryable and fully reconstructable:

- a `metadata` table holds the document with its entries emptied (the kind plus all
  data not attached to an individual entry: schema/version, the SARIF tool driver and
  rules, the CycloneDX metadata and dependencies);
- an entry table (`findings` for SARIF, `components` for CycloneDX, from
  `artifact.records()`) holds one row per entry, with parsed columns for querying AND
  that entry's raw JSON in a `document` column, so a single entry reconstructs alone.

`read` rebuilds the exact original document by splicing the entry rows (in their
stored order) back into the metadata shell.
"""

import copy
import json
from collections.abc import Sequence
from typing import Any

from repo_scanner.execution.process import Failure
from repo_scanner.ioutil import sqlitedb
from repo_scanner.ioutil.sqlitedb import Table, TableSchema
from repo_scanner.scans import cyclonedx, sarif
from repo_scanner.scans.model import Artifact, ArtifactKind

# db schema for metadata table: one row per artifact, holding its kind and its
# emptied document shell.
_METADATA = TableSchema(
    name="metadata",
    columns=("kind", "document"),
    create="CREATE TABLE metadata (kind TEXT, document TEXT)",
    insert="INSERT INTO metadata VALUES (?, ?)",
    select="SELECT * FROM metadata ORDER BY rowid",
)


def write(artifacts: Sequence[Artifact], path: str) -> Failure | None:
    """Write `artifacts` to a new sqlite report database at `path`.

    Each artifact contributes a `metadata` row (its kind plus its emptied shell) and
    its own entry table (`findings` for SARIF, `components` for CycloneDX). A report
    holds at most one artifact per kind, so those entry-table names never collide.

    Every table goes in one transaction, so a report is either whole or absent.

    Returns:
        None on success, or a Failure if the database could not be opened.
    """
    session, error = sqlitedb.connect(path)
    if session is None:
        return Failure(reason=error or f"could not write {path}")
    with session:
        session.create(_METADATA)
        session.insert(
            Table(
                _METADATA,
                [
                    (artifact.kind.value, json.dumps(_shell(artifact)))
                    for artifact in artifacts
                ],
            )
        )
        for artifact in artifacts:
            records = artifact.records()
            session.create(records.schema)
            session.insert(records)
    return None


def read(path: str) -> list[Artifact]:
    """The artifacts reconstructed from the report database at `path`.

    Empty if `path` is not a reposcan report database (no `metadata` table).
    """
    session, _ = sqlitedb.connect(path)
    if session is None:
        return []
    artifacts: list[Artifact] = []
    with session:
        if not session.has_table(_METADATA.name):
            return []
        for kind, shell_json in session.query(_METADATA.select):
            shell = json.loads(shell_json)
            if kind == ArtifactKind.SARIF.value:
                rows = session.query(sarif.FINDINGS.select)
                for run, document in _column(rows, sarif.FINDINGS, "run", "document"):
                    shell["runs"][int(run)]["results"].append(json.loads(document))
                artifacts.append(sarif.SarifDocument(shell))
            elif kind == ArtifactKind.CYCLONEDX.value:
                rows = session.query(cyclonedx.COMPONENTS.select)
                shell["components"] = [
                    json.loads(document)
                    for (document,) in _column(rows, cyclonedx.COMPONENTS, "document")
                ]
                artifacts.append(cyclonedx.CycloneDxDocument(shell))
    return artifacts


def _column(
    rows: Sequence[tuple[Any, ...]], schema: TableSchema, *names: str
) -> list[tuple[Any, ...]]:
    """The named columns of each row, looked up by position in `schema`."""
    indexes = [schema.columns.index(name) for name in names]
    return [tuple(row[index] for index in indexes) for row in rows]


def _shell(artifact: Artifact) -> dict:
    """The artifact's document with its entries emptied (the non-entry metadata)."""
    document = copy.deepcopy(artifact.to_dict())
    if artifact.kind is ArtifactKind.SARIF:
        for run in document.get("runs", []):
            run["results"] = []
    else:
        document["components"] = []
    return document

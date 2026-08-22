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

from repo_scanner.ioutil import sqlitedb
from repo_scanner.ioutil.sqlitedb import Table
from repo_scanner.scans import cyclonedx, sarif
from repo_scanner.scans.model import Artifact, ArtifactKind


def write(artifacts: Sequence[Artifact], path: str) -> None:
    """Write `artifacts` to a new sqlite report database at `path`.

    Each artifact contributes a `metadata` row (its kind plus its emptied shell) and
    its own entry table (`findings` for SARIF, `components` for CycloneDX). A report
    holds at most one artifact per kind, so those entry-table names never collide.
    """
    metadata = Table(
        "metadata",
        ("kind", "document"),
        [(artifact.kind.value, json.dumps(_shell(artifact))) for artifact in artifacts],
    )
    sqlitedb.write(path, [metadata, *(artifact.records() for artifact in artifacts)])


def read(path: str) -> list[Artifact]:
    """The artifacts reconstructed from the report database at `path`.

    Empty if `path` is not a reposcan report database (no `metadata` table).
    """
    metadata = sqlitedb.read(path, "metadata")
    if metadata is None:
        return []
    artifacts: list[Artifact] = []
    for kind, shell_json in metadata.rows:
        shell = json.loads(shell_json)
        if kind == ArtifactKind.SARIF.value:
            findings = sqlitedb.read(path, "findings")
            for run, document in _column(findings, "run", "document"):
                shell["runs"][int(run)]["results"].append(json.loads(document))
            artifacts.append(sarif.SarifDocument(shell))
        elif kind == ArtifactKind.CYCLONEDX.value:
            components = sqlitedb.read(path, "components")
            shell["components"] = [
                json.loads(doc) for (doc,) in _column(components, "document")
            ]
            artifacts.append(cyclonedx.CycloneDxDocument(shell))
    return artifacts


def _column(table: Table | None, *names: str) -> list[tuple[str, ...]]:
    """Retrieve the named columns from each row of `table`."""
    if table is None:
        return []
    indexes = [table.columns.index(name) for name in names]
    return [tuple(row[index] for index in indexes) for row in table.rows]


def _shell(artifact: Artifact) -> dict:
    """The artifact's document with its entries emptied (the non-entry metadata)."""
    document = copy.deepcopy(artifact.to_dict())
    if artifact.kind is ArtifactKind.SARIF:
        for run in document.get("runs", []):
            run["results"] = []
    else:
        document["components"] = []
    return document

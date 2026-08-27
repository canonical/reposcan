# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the sqlite report format (repo_scanner.scans.reportdb).

The domain mapping between an artifact and the generic tabular store: an artifact
round-trips exactly, its entries land in a queryable table, and the non-entry
metadata is retained separately.
"""

import json
import os
import sqlite3
import tempfile

from repo_scanner.scans import cyclonedx, reportdb, sarif


def _bom() -> cyclonedx.CycloneDxDocument:
    return cyclonedx.CycloneDxDocument(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [{"type": "library", "name": "flask", "version": "3.0.0"}],
        }
    )


def _query(path: str, sql: str) -> list[tuple]:
    connection = sqlite3.connect(path)
    try:
        return connection.execute(sql).fetchall()
    finally:
        connection.close()


def _sarif() -> sarif.SarifDocument:
    run = sarif.SarifRun.from_results(
        "t",
        "1.0",
        [
            sarif.SarifResult.build(
                "R1", "insecure hash function", "a.py", 3, "t", "", level="error"
            )
        ],
    )
    return sarif.SarifDocument.from_runs([run])


def test_write_then_read_reconstructs_the_whole_artifact() -> None:
    artifact = _bom()
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "r.db")
        reportdb.write([artifact], path)
        (restored,) = reportdb.read(path)
        assert restored.to_dict() == artifact.to_dict()


def test_write_then_read_round_trips_both_a_sarif_and_a_cyclonedx_together() -> None:
    findings, sbom = _sarif(), _bom()
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "r.db")
        reportdb.write([findings, sbom], path)
        restored = reportdb.read(path)
    by_kind = {artifact.kind: artifact for artifact in restored}
    assert by_kind[findings.kind].to_dict() == findings.to_dict()
    assert by_kind[sbom.kind].to_dict() == sbom.to_dict()


def test_sbom_gets_a_queryable_components_table() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "r.db")
        reportdb.write([_bom()], path)
        rows = _query(
            path, "SELECT name, version, type, purl, scanners FROM components"
        )
    assert rows == [("flask", "3.0.0", "library", "", "")]


def test_findings_get_a_queryable_findings_table_with_split_location() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "r.db")
        reportdb.write([_sarif()], path)
        rows = _query(path, "SELECT rule, level, uri, line, message FROM findings")
    assert rows == [("R1", "error", "a.py", "3", "insecure hash function")]


def test_each_row_keeps_its_raw_json_and_metadata_holds_the_rest() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "r.db")
        reportdb.write([_bom()], path)
        (component_json,) = _query(path, "SELECT document FROM components")[0]
        (kind, shell_json) = _query(path, "SELECT kind, document FROM metadata")[0]
    assert json.loads(component_json)["name"] == "flask"  # per-row reconstruction
    shell = json.loads(shell_json)
    assert kind == "cyclonedx"
    assert shell["specVersion"] == "1.5"  # non-entry metadata is retained
    assert shell["components"] == []  # entries live only in the components table


def test_read_returns_empty_for_a_non_report_database() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "other.db")
        connection = sqlite3.connect(path)
        connection.execute("CREATE TABLE unrelated (a TEXT)")
        connection.commit()
        connection.close()
        assert reportdb.read(path) == []

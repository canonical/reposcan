# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Importing one database into another: write two, import one, read the result."""

import os
import sqlite3
import tempfile
from pathlib import Path

from reposcan.db import read, write
from reposcan.db.model import ImportCounts
from reposcan.result import Err
from reposcan.scans import cyclonedx, sarif
from reposcan.scans.analysis import Analysis, ScanRecord, ScanStatus
from reposcan.scans.model import ArtifactKind
from reposcan.scans.repo import ProjectIdentity, RepositoryState


def _build_analysis(uuid: str, *scans: ScanRecord, produced_by: str = "") -> Analysis:
    analysis = Analysis(
        uuid=uuid,
        started_at="2026-10-01T10:00:00Z",
        finished_at="2026-10-01T10:05:00Z",
        reposcan_version="0.2.0",
        repository=RepositoryState(
            identity=ProjectIdentity("app", root_commit="r00t"),
            commit_sha="c0ffee",
            branch="main",
        ),
        produced_by=produced_by,
    )
    for scan in scans:
        analysis.add(scan)
    return analysis


def _build_findings_scan(*rules: str) -> ScanRecord:
    """A sast scan reporting each rule once, in a file and line of its own."""
    findings = []
    for index, rule in enumerate(rules):
        finding = sarif.SarifResult.build(
            rule, "finding", f"{rule}.py", index + 1, "semgrep", "", "error"
        )
        finding.result["partialFingerprints"] = {"primaryLocationLineHash": rule}
        findings.append(finding)
    run = sarif.SarifRun.from_results("semgrep", "1.0", findings)
    run.set_automation_id("reposcan/sast/")
    return ScanRecord(
        category="sast",
        kind=ArtifactKind.SARIF,
        started_at="2026-10-01T10:00:00Z",
        finished_at="2026-10-01T10:01:00Z",
        status=ScanStatus.COMPLETE,
        produced=run,
    )


def _build_sbom_scan() -> ScanRecord:
    document = cyclonedx.CycloneDxDocument(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {"type": "library", "name": "flask", "purl": "pkg:pypi/flask@3.0.0"}
            ],
        }
    )
    return ScanRecord(
        category="sbom",
        kind=ArtifactKind.CYCLONEDX,
        started_at="2026-10-01T10:02:00Z",
        finished_at="2026-10-01T10:03:00Z",
        status=ScanStatus.COMPLETE,
        produced=document,
    )


def _write_database(path: str, *analyses: Analysis) -> None:
    for analysis in analyses:
        assert write.write_analysis(path, analysis) is None


def _query(path: str, sql: str) -> list[tuple]:
    connection = sqlite3.connect(path)
    try:
        return connection.execute(sql).fetchall()
    finally:
        connection.close()


def test_an_imported_analysis_reads_back_exactly_as_the_source_holds_it() -> None:
    with tempfile.TemporaryDirectory() as directory:
        source = os.path.join(directory, "source.db")
        destination = os.path.join(directory, "destination.db")
        _write_database(
            source,
            _build_analysis("u1", _build_findings_scan("R1", "R2"), _build_sbom_scan()),
            _build_analysis("u2", _build_findings_scan("R2")),
        )
        # A database shipped elsewhere is often rollback-journalled (VACUUM INTO
        # writes one), and opening it read-write would switch it to WAL.
        connection = sqlite3.connect(source)
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.close()
        before = Path(source).read_bytes()
        write.import_database(source, destination, produced_by="ci")
        assert Path(source).read_bytes() == before
        for analysis_id in (1, 2):
            imported = read.list_artifacts(destination, analysis_id)
            original = read.list_artifacts(source, analysis_id)
            assert [artifact.to_dict() for artifact in imported] == [
                artifact.to_dict() for artifact in original
            ]
        for statement in (
            "SELECT uuid, started_at, finished_at, target_name, commit_sha, status "
            "FROM analysis ORDER BY analysis_id",
            "SELECT category, artifact_kind, started_at, finished_at, status "
            "FROM scan ORDER BY scan_id",
        ):
            assert _query(destination, statement) == _query(source, statement)


def test_an_issue_both_databases_knew_becomes_one_issue() -> None:
    with tempfile.TemporaryDirectory() as directory:
        source = os.path.join(directory, "source.db")
        destination = os.path.join(directory, "destination.db")
        _write_database(source, _build_analysis("a1", _build_findings_scan("X", "Z")))
        _write_database(
            destination, _build_analysis("b1", _build_findings_scan("X", "Y"))
        )
        assert not isinstance(write.import_database(source, destination, "ci"), Err)
        spans = {
            issue.rule: (issue.first_seen_analysis, issue.last_seen_analysis)
            for issue in read.list_issues(destination, project_id=1)
        }
    # X was reported to both: one issue spanning both analyses. Y and Z were each
    # known to one side, and both survive.
    assert spans == {"X": (1, 2), "Y": (1, 1), "Z": (2, 2)}


def test_produced_by_is_stamped_only_where_the_source_left_it_empty() -> None:
    with tempfile.TemporaryDirectory() as directory:
        source = os.path.join(directory, "source.db")
        destination = os.path.join(directory, "destination.db")
        _write_database(
            source,
            _build_analysis("own", _build_findings_scan("R1")),
            _build_analysis(
                "relayed", _build_findings_scan("R1"), produced_by="laptop"
            ),
        )
        write.import_database(source, destination, produced_by="ci")
        rows = _query(destination, "SELECT uuid, produced_by FROM analysis")
    assert sorted(rows) == [("own", "ci"), ("relayed", "laptop")]


def test_an_import_drops_raw_secrets_unless_asked_to_retain_them() -> None:
    finding = sarif.SarifResult.build(
        "AWS", "AWS secret detected", "config.py", 3, "trufflehog", "", "warning"
    )
    finding.add_fingerprint("secretHash/v1", "hash-of-the-secret")
    finding.set_secret("RAWSECRETEXAMPLE")
    run = sarif.SarifRun.from_results("trufflehog", "3.95.8", [finding])
    run.set_automation_id("reposcan/secrets/")
    scan = ScanRecord(
        category="secrets",
        kind=ArtifactKind.SARIF,
        started_at="2026-10-01T10:00:00Z",
        finished_at="2026-10-01T10:01:00Z",
        status=ScanStatus.COMPLETE,
        produced=run,
    )
    with tempfile.TemporaryDirectory() as directory:
        source = os.path.join(directory, "source.db")
        _write_database(source, _build_analysis("u1", scan))
        imported_secrets = []
        for retain_secrets in (False, True):
            destination = os.path.join(directory, f"retain-{retain_secrets}.db")
            write.import_database(
                source, destination, "ci", retain_secrets=retain_secrets
            )
            (artifact,) = read.list_artifacts(destination)
            (imported,) = artifact.to_dict()["runs"][0]["results"]
            secret = imported["properties"].get("reposcan:secret")
            imported_secrets.append((secret, imported["fingerprints"]))
    # The hash a secret is matched by stays either way.
    fingerprints = {"secretHash/v1": "hash-of-the-secret"}
    assert imported_secrets == [
        (None, fingerprints),
        ("RAWSECRETEXAMPLE", fingerprints),
    ]


def test_a_source_that_is_not_a_current_reposcan_database_is_refused() -> None:
    with tempfile.TemporaryDirectory() as directory:
        destination = os.path.join(directory, "destination.db")
        text = os.path.join(directory, "notes.txt")
        Path(text).write_text("not a database")
        # A whole database, written by a reposcan with a newer schema.
        newer = os.path.join(directory, "newer.db")
        _write_database(newer, _build_analysis("u1", _build_findings_scan("R1")))
        connection = sqlite3.connect(newer)
        connection.execute("PRAGMA user_version = 99")
        connection.close()
        # A view standing in for a table, as a crafted database could hold.
        posed = os.path.join(directory, "posed.db")
        _write_database(posed, _build_analysis("u1", _build_findings_scan("R1")))
        connection = sqlite3.connect(posed)
        connection.execute("ALTER TABLE analysis RENAME TO analysis_rows")
        connection.execute("CREATE VIEW analysis AS SELECT * FROM analysis_rows")
        connection.commit()
        connection.close()
        missing = os.path.join(directory, "missing.db")
        for source in (text, newer, posed, missing):
            outcome = write.import_database(source, destination, "ci")
            assert isinstance(outcome, Err), source
            assert not os.path.exists(destination), source
        assert not os.path.exists(missing)  # reading never creates the source


def test_a_malformed_analysis_stops_the_import_and_a_rerun_finishes_it() -> None:
    with tempfile.TemporaryDirectory() as directory:
        source = os.path.join(directory, "source.db")
        destination = os.path.join(directory, "destination.db")
        _write_database(
            source,
            _build_analysis("u1", _build_findings_scan("R1")),
            _build_analysis("u2", _build_findings_scan("R2")),
            _build_analysis("u3", _build_findings_scan("R3")),
        )
        select_u2 = "SELECT scan_id FROM scan WHERE analysis_id = 2"
        ((intact,),) = _query(
            source,
            f"SELECT result_json FROM issue_report WHERE scan_id IN ({select_u2})",
        )
        connection = sqlite3.connect(source)
        update = (
            f"UPDATE issue_report SET result_json = ? WHERE scan_id IN ({select_u2})"
        )
        connection.execute(update, ("{not json",))
        connection.commit()
        first_outcome = write.import_database(source, destination, "ci")
        assert isinstance(first_outcome, Err)
        assert "u2" in first_outcome.msg
        # Each analysis commits on its own: the one before the failure stays.
        assert _query(destination, "SELECT uuid FROM analysis") == [("u1",)]
        connection.execute(update, (intact,))
        connection.commit()
        connection.close()
        rerun_outcome = write.import_database(source, destination, "ci")
        assert rerun_outcome == ImportCounts(imported=2, skipped=1)
        uuids = _query(destination, "SELECT uuid FROM analysis ORDER BY analysis_id")
    assert uuids == [("u1",), ("u2",), ("u3",)]

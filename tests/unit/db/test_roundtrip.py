# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Roundtrip test for the history db: write then read a scan; assert equality."""

import os
import sqlite3
import tempfile

from repo_scanner.db import read, write
from repo_scanner.db.model import RunRecord, RunStatus, ScanRecord
from repo_scanner.execution.process import Failure
from repo_scanner.scans import cyclonedx, sarif
from repo_scanner.scans.model import ArtifactKind, ToolInvocationRecord
from repo_scanner.scans.repo import ProjectIdentity, RepositoryState


def _state(name: str = "repo-scanner", root: str = "abc") -> RepositoryState:
    return RepositoryState(
        identity=ProjectIdentity(name, root_commit=root),
        commit_sha="c0ffee",
        branch="main",
    )


def _scan(uuid: str = "u1", state: RepositoryState | None = None) -> ScanRecord:
    return ScanRecord(
        uuid=uuid,
        started_at="2026-08-24T10:00:00Z",
        finished_at="2026-08-24T10:01:00Z",
        reposcan_version="0.1.0",
        repository=state or _state(),
    )


def _findings_run() -> RunRecord:
    result = sarif.SarifResult.build("R1", "boom", "a.py", 3, "semgrep", "", "error")
    result.result["partialFingerprints"] = {"primaryLocationLineHash": "deadbeef"}
    run = sarif.SarifRun.from_results("semgrep", "1.0", [result])
    run.set_automation_id("reposcan/sast/")
    invocations = [
        ToolInvocationRecord(
            tool="semgrep",
            args=["--json"],
            version="1.0",
            command=("/opt/semgrep", "--json"),
            working_directory="/scan/x",
            environment={"SEMGREP_SEND_METRICS": "off"},
            exit_code=0,
            successful=True,
        )
    ]
    # The driver records provenance onto the artifact and hands the same records to
    # the store, so the round trip is against a document that already carries them.
    run.record_invocations(invocations)
    return RunRecord(
        category="sast",
        kind=ArtifactKind.SARIF,
        started_at="2026-08-24T10:00:00Z",
        finished_at="2026-08-24T10:00:30Z",
        status=RunStatus.COMPLETE,
        produced=run,
        invocations=invocations,
    )


def _sbom_run() -> RunRecord:
    document = cyclonedx.CycloneDxDocument(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [{"type": "library", "name": "flask", "version": "3.0.0"}],
        }
    )
    return RunRecord(
        category="sbom",
        kind=ArtifactKind.CYCLONEDX,
        started_at="2026-08-24T10:01:00Z",
        finished_at="2026-08-24T10:01:30Z",
        status=RunStatus.COMPLETE,
        produced=document,
    )


def _query(path: str, sql: str) -> list[tuple]:
    connection = sqlite3.connect(path)
    try:
        return connection.execute(sql).fetchall()
    finally:
        connection.close()


def test_a_scan_round_trips_every_artifact_it_recorded() -> None:
    findings, sbom = _findings_run(), _sbom_run()
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "history.db")
        assert write.scan(path, _scan(), [findings, sbom]) is None
        restored = read.artifacts(path)
    # The scan types come back as runs of one document, as the scan emitted them.
    produced = findings.produced
    assert isinstance(produced, sarif.SarifRun)  # a findings run, not an inventory
    assert [artifact.to_dict() for artifact in restored] == [
        sarif.SarifDocument.from_runs([produced]).to_dict(),
        sbom.produced.to_dict(),
    ]


def test_entries_land_in_queryable_tables_alongside_their_raw_json() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "history.db")
        write.scan(path, _scan(), [_findings_run(), _sbom_run()])
        findings = _query(
            path,
            "SELECT rule, level, uri, line, message, "
            "json_extract(partial_fingerprints, '$.primaryLocationLineHash') "
            "FROM findings",
        )
        components = _query(path, "SELECT name, version, type FROM components")
        shells = _query(
            path, "SELECT category, artifact_shell FROM run ORDER BY run_id"
        )
        invocations = _query(path, "SELECT tool, exit_code, successful FROM invocation")
    assert findings == [("R1", "error", "a.py", "3", "boom", "deadbeef")]
    assert components == [("flask", "3.0.0", "library")]
    assert invocations == [("semgrep", 0, 1)]
    # The shell keeps the metadata and none of the entries.
    assert shells[0][0] == "sast"
    assert '"results": []' in shells[0][1]
    assert '"automationDetails"' in shells[0][1]


def test_the_scan_records_the_repository_it_covered() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "history.db")
        write.scan(path, _scan(), [_findings_run()])
        (scan_row,) = _query(
            path, "SELECT commit_sha, branch, dirty, shallow FROM scan"
        )
        (project,) = _query(path, "SELECT name, root_commit FROM project")
    assert scan_row == ("c0ffee", "main", 0, 0)
    assert project == ("repo-scanner", "abc")


def test_a_second_scan_appends_and_the_same_scan_twice_does_not() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "history.db")
        write.scan(path, _scan("u1"), [_findings_run()])
        write.scan(path, _scan("u2"), [_findings_run()])
        write.scan(path, _scan("u1"), [_findings_run()])  # already recorded
        assert [summary.uuid for summary in read.scans(path)] == ["u1", "u2"]
        # One repository, however many scans of it are recorded.
        assert len(read.projects(path)) == 1
        # read_artifacts defaults to the most recent scan.
        assert len(read.artifacts(path)) == 1


def test_a_different_repository_becomes_a_second_project() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "history.db")
        write.scan(path, _scan("u1"), [_findings_run()])
        other = _scan("u2", _state(name="other", root="zzz"))
        write.scan(path, other, [_findings_run()])
        assert [p.name for p in read.projects(path)] == ["repo-scanner", "other"]


def test_a_database_of_another_schema_version_is_refused_not_misread() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "old.db")
        connection = sqlite3.connect(path)
        connection.execute("PRAGMA user_version = 99")
        connection.close()
        failure = write.scan(path, _scan(), [_findings_run()])
        assert isinstance(failure, Failure)
        assert "version 99" in failure.reason
        assert read.artifacts(path) == []
        assert read.scans(path) == []
        assert read.projects(path) == []


def test_a_file_that_is_not_a_database_is_refused_before_anything_is_written() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "notes.txt")
        with open(path, "w") as handle:
            handle.write("not a database")
        failure = write.scan(path, _scan(), [_findings_run()])
        assert isinstance(failure, Failure)
        assert "not a sqlite database" in failure.reason
        # Refused whole: the file is left exactly as it was.
        with open(path) as handle:
            assert handle.read() == "not a database"


def test_an_empty_file_reserved_by_the_caller_becomes_a_new_database() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "reserved.db")
        with open(path, "x"):
            pass  # how the output layer reserves a path before writing to it
        assert write.scan(path, _scan(), [_findings_run()]) is None
        assert len(read.artifacts(path)) == 1

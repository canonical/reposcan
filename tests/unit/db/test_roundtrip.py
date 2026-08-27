# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Roundtrip test for the db: write then read an analysis; assert equality."""

import os
import sqlite3
import tempfile

from repo_scanner.db import read, write
from repo_scanner.db.model import (
    AnalysisRecord,
    ScanRecord,
    ScanStatus,
)
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


def _analysis(uuid: str = "u1", state: RepositoryState | None = None) -> AnalysisRecord:
    return AnalysisRecord(
        uuid=uuid,
        started_at="2026-08-24T10:00:00Z",
        finished_at="2026-08-24T10:01:00Z",
        reposcan_version="0.1.0",
        repository=state or _state(),
    )


def _findings_scan() -> ScanRecord:
    result = sarif.SarifResult.build(
        "R1", "insecure hash function", "a.py", 3, "semgrep", "", "error"
    )
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
    run.record_invocations(invocations)
    return ScanRecord(
        category="sast",
        kind=ArtifactKind.SARIF,
        started_at="2026-08-24T10:00:00Z",
        finished_at="2026-08-24T10:00:30Z",
        status=ScanStatus.COMPLETE,
        produced=run,
    )


def _sbom_scan(*versions: str) -> ScanRecord:
    document = cyclonedx.CycloneDxDocument(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {
                    "type": "library",
                    "name": "flask",
                    "version": version,
                    "purl": f"pkg:pypi/flask@{version}",
                }
                for version in (versions or ("3.0.0",))
            ],
        }
    )
    return ScanRecord(
        category="sbom",
        kind=ArtifactKind.CYCLONEDX,
        started_at="2026-08-24T10:01:00Z",
        finished_at="2026-08-24T10:01:30Z",
        status=ScanStatus.COMPLETE,
        produced=document,
    )


def _query(path: str, sql: str) -> list[tuple]:
    connection = sqlite3.connect(path)
    try:
        return connection.execute(sql).fetchall()
    finally:
        connection.close()


def test_an_analysis_round_trips_every_artifact_it_recorded() -> None:
    findings, sbom = _findings_scan(), _sbom_scan()
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "history.db")
        assert write.analysis(path, _analysis(), [findings, sbom]) is None
        restored = read.artifacts(path)
    produced = findings.produced
    assert isinstance(produced, sarif.SarifRun)  # a findings run, not an inventory
    assert [artifact.to_dict() for artifact in restored] == [
        sarif.SarifDocument.from_runs([produced]).to_dict(),
        sbom.produced.to_dict(),
    ]


def test_reports_land_in_queryable_tables_alongside_their_raw_json() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "history.db")
        write.analysis(path, _analysis(), [_findings_scan(), _sbom_scan()])
        findings = _query(
            path,
            "SELECT i.rule, r.level, r.uri, r.line, r.message, "
            "json_extract(r.partial_fingerprints, '$.primaryLocationLineHash') "
            "FROM issue_report r JOIN issue i ON i.issue_id = r.issue_id",
        )
        components = _query(path, "SELECT name, version, type FROM component_report")
        shells = _query(
            path, "SELECT category, artifact_shell FROM scan ORDER BY scan_id"
        )
        invocations = _query(path, "SELECT tool, exit_code, successful FROM invocation")
    assert findings == [
        ("R1", "error", "a.py", "3", "insecure hash function", "deadbeef")
    ]
    assert components == [("flask", "3.0.0", "library")]
    assert invocations == [("semgrep", 0, 1)]
    # The shell keeps the metadata and none of the entries.
    assert shells[0][0] == "sast"
    assert '"results": []' in shells[0][1]
    assert '"automationDetails"' in shells[0][1]


def test_provenance_is_not_lost() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "history.db")
        run = sarif.SarifRun(
            {
                "tool": {"driver": {"name": "some-tool"}},
                "results": [],
                "invocations": [{"commandLine": "some-tool --scan", "exitCode": 0}],
            }
        )
        assert run.tool_invocations == []  # nothing recorded; only the raw JSON
        write.analysis(
            path,
            _analysis(),
            [
                ScanRecord(
                    category="sast",
                    kind=ArtifactKind.SARIF,
                    started_at="2026-08-24T10:00:00Z",
                    finished_at="2026-08-24T10:00:30Z",
                    status=ScanStatus.COMPLETE,
                    produced=run,
                )
            ],
        )
        (restored,) = read.artifacts(path)
    (rebuilt,) = restored.to_dict()["runs"]
    assert rebuilt["invocations"] == [
        {"commandLine": "some-tool --scan", "exitCode": 0}
    ]


def test_the_analysis_records_the_repository_it_covered() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "history.db")
        write.analysis(path, _analysis(), [_findings_scan()])
        (scan_row,) = _query(
            path, "SELECT commit_sha, branch, dirty, shallow FROM analysis"
        )
        (project,) = _query(path, "SELECT name, root_commit FROM project")
    assert scan_row == ("c0ffee", "main", 0, 0)
    assert project == ("repo-scanner", "abc")


def test_a_second_analysis_appends_and_the_same_one_twice_does_not() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "history.db")
        write.analysis(path, _analysis("u1"), [_findings_scan()])
        write.analysis(path, _analysis("u2"), [_findings_scan()])
        write.analysis(path, _analysis("u1"), [_findings_scan()])  # already recorded
        assert [summary.uuid for summary in read.analyses(path)] == ["u1", "u2"]
        # One repository, however many scans of it are recorded.
        assert len(read.projects(path)) == 1
        # read_artifacts defaults to the most recent scan.
        assert len(read.artifacts(path)) == 1


def test_a_different_repository_becomes_a_second_project() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "history.db")
        write.analysis(path, _analysis("u1"), [_findings_scan()])
        other = _analysis("u2", _state(name="other", root="zzz"))
        write.analysis(path, other, [_findings_scan()])
        assert [p.name for p in read.projects(path)] == ["repo-scanner", "other"]


def test_a_database_of_another_schema_version_is_refused_not_misread() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "old.db")
        connection = sqlite3.connect(path)
        connection.execute("PRAGMA user_version = 99")
        connection.close()
        failure = write.analysis(path, _analysis(), [_findings_scan()])
        assert isinstance(failure, Failure)
        assert "version 99" in failure.reason
        assert read.artifacts(path) == []
        assert read.analyses(path) == []
        assert read.projects(path) == []


def test_a_file_that_is_not_a_database_is_refused_before_anything_is_written() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "notes.txt")
        with open(path, "w") as handle:
            handle.write("not a database")
        failure = write.analysis(path, _analysis(), [_findings_scan()])
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
        assert write.analysis(path, _analysis(), [_findings_scan()]) is None
        assert len(read.artifacts(path)) == 1


def _secret_scan(line: int = 4, line_hash: str | None = None) -> ScanRecord:
    result = sarif.SarifResult.build("AWS", "leak", "conf.py", line, "trufflehog", "")
    result.add_fingerprint("secretHash", "sha256:abcd")
    if line_hash is not None:
        result.result["partialFingerprints"] = {"primaryLocationLineHash": line_hash}
    run = sarif.SarifRun.from_results("trufflehog", "3.95.8", [result])
    run.set_automation_id("reposcan/secrets/")
    return ScanRecord(
        category="secrets",
        kind=ArtifactKind.SARIF,
        started_at="2026-08-24T10:00:00Z",
        finished_at="2026-08-24T10:00:30Z",
        status=ScanStatus.COMPLETE,
        produced=run,
    )


def test_an_issue_spans_the_analyses_that_reported_it() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "history.db")
        write.analysis(path, _analysis("u1"), [_findings_scan(), _sbom_scan()])
        write.analysis(path, _analysis("u2"), [_findings_scan(), _sbom_scan()])
        write.analysis(path, _analysis("u3"), [_findings_scan(), _sbom_scan()])
        findings = read.issues(path, project_id=1)
        components = read.components(path, project_id=1)
    # The same finding and the same component throughout, not three of each.
    assert len(findings) == len(components) == 1
    for issue in (*findings, *components):
        assert (issue.first_seen_analysis, issue.last_seen_analysis) == (1, 3)


def test_a_component_survives_a_version_change() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "history.db")
        write.analysis(path, _analysis("u1"), [_sbom_scan("3.0.0")])
        write.analysis(path, _analysis("u2"), [_sbom_scan("3.1.0")])
        (issue,) = read.components(path, project_id=1)
        versions = _query(path, "SELECT version FROM component_report ORDER BY scan_id")
    assert (issue.first_seen_analysis, issue.last_seen_analysis) == (1, 2)
    assert versions == [("3.0.0",), ("3.1.0",)]  # one issue, two observed versions


def _spans(path: str) -> list[tuple[str, int, int, int]]:
    """Every version span of the only component in the only project."""
    (component,) = read.components(path, project_id=1)
    return [
        (
            span.version,
            span.first_seen_analysis,
            span.last_seen_analysis,
            span.analysis_count,
        )
        for span in read.versions(path, component.component_id)
    ]


def test_one_version_pinned_twice_in_an_analysis_counts_as_one_sighting() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "history.db")
        # Two lockfiles in the repository pin the same version of the same package.
        write.analysis(path, _analysis("u1"), [_sbom_scan("3.0.0", "3.0.0")])
        spans = _spans(path)
    assert spans == [("3.0.0", 1, 1, 1)]


def test_each_version_spans_from_its_first_sighting_to_its_last() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "history.db")
        write.analysis(path, _analysis("u1"), [_sbom_scan("1.0.0")])
        write.analysis(path, _analysis("u2"), [_sbom_scan("2.0.0")])
        write.analysis(path, _analysis("u3"), [_sbom_scan("1.0.0")])
        spans = _spans(path)
    # A span per version, running from the earliest analysis that saw it to the
    # latest. 1.0.0 was rolled back to, so its span covers all three analyses while
    # only two of them saw it: the count is the only thing that says so.
    assert spans == [("1.0.0", 1, 3, 2), ("2.0.0", 2, 2, 1)]


def test_two_projects_keep_their_issues_apart() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "history.db")
        write.analysis(path, _analysis("u1"), [_findings_scan()])
        other = _analysis("u2", _state(name="other", root="zzz"))
        write.analysis(path, other, [_findings_scan()])
        first, second = read.issues(path, 1), read.issues(path, 2)
    # Both projects ingested the very same run, so the report is identical in every
    # respect; belonging to another repository is what makes it a separate issue.
    assert len(first) == len(second) == 1
    assert first[0].issue_id != second[0].issue_id


def test_a_reports_fingerprints_are_queryable() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "history.db")
        write.analysis(path, _analysis(), [_secret_scan()])
        rows = _query(
            path,
            "SELECT json_extract(fingerprints, '$.secretHash') FROM issue_report",
        )
    assert rows == [("sha256:abcd",)]


def _finding_scan(line: int = 3, line_hash: str | None = "deadbeef") -> ScanRecord:
    result = sarif.SarifResult.build(
        "R1", "insecure hash function", "a.py", line, "semgrep", "", "error"
    )
    if line_hash is not None:
        result.result["partialFingerprints"] = {"primaryLocationLineHash": line_hash}
    run = sarif.SarifRun.from_results("semgrep", "1.0", [result])
    run.set_automation_id("reposcan/sast/")
    return ScanRecord(
        category="sast",
        kind=ArtifactKind.SARIF,
        started_at="2026-08-26T10:00:00Z",
        finished_at="2026-08-26T10:00:30Z",
        status=ScanStatus.COMPLETE,
        produced=run,
    )


def test_a_report_that_gains_a_line_hash_stays_one_issue() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "history.db")
        write.analysis(path, _analysis("u1"), [_finding_scan(line_hash=None)])
        write.analysis(path, _analysis("u2"), [_finding_scan(line_hash="abc:1")])
        issues = read.issues(path, project_id=1)
    assert len(issues) == 1  # issue was correctly identified as already-known
    assert (issues[0].first_seen_analysis, issues[0].last_seen_analysis) == (1, 2)


def test_an_issue_whose_line_moves_stays_one_issue() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "history.db")
        write.analysis(path, _analysis("u1"), [_finding_scan(line=3)])
        # same line content, new line number.
        write.analysis(path, _analysis("u2"), [_finding_scan(line=40)])
        issues = read.issues(path, project_id=1)
    assert len(issues) == 1
    assert (issues[0].first_seen_analysis, issues[0].last_seen_analysis) == (1, 2)


def test_a_report_whose_line_content_changed_is_a_different_issue() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "history.db")
        write.analysis(path, _analysis("u1"), [_finding_scan(line_hash="abc:1")])
        write.analysis(path, _analysis("u2"), [_finding_scan(line_hash="xyz:1")])
        issues = read.issues(path, project_id=1)
    # Same rule and place, but the line content changed.
    assert len(issues) == 2


def _sca_scan(rule: str, uri: str, line: int, line_hash: str) -> ScanRecord:
    result = sarif.SarifResult.build(
        rule, "vulnerable dependency", uri, line, "trivy", ""
    )
    result.result["partialFingerprints"] = {"primaryLocationLineHash": line_hash}
    run = sarif.SarifRun.from_results("trivy", "1.0", [result])
    run.set_automation_id("reposcan/sca/")
    return ScanRecord(
        category="sca",
        kind=ArtifactKind.SARIF,
        started_at="2026-08-26T10:00:00Z",
        finished_at="2026-08-26T10:00:30Z",
        status=ScanStatus.COMPLETE,
        produced=run,
    )


def test_a_fingerprint_seen_once_is_remembered_after_an_analysis_without_it() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "history.db")
        # Seen with a line hash, then without it, then with it again.
        write.analysis(
            path, _analysis("u1"), [_finding_scan(line=3, line_hash="abc:1")]
        )
        # matched based on rule id + line num
        write.analysis(path, _analysis("u2"), [_finding_scan(line=3, line_hash=None)])
        # matched based on rule id + line hash
        write.analysis(
            path, _analysis("u3"), [_finding_scan(line=40, line_hash="abc:1")]
        )
        issues = read.issues(path, project_id=1)
    # all were identified as the same finding
    assert len(issues) == 1
    assert (issues[0].first_seen_analysis, issues[0].last_seen_analysis) == (1, 3)


def test_a_remembered_fingerprint_takes_the_newest_value_for_its_name() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "history.db")
        # The same secret, on a line edited between the two scans. The two are
        # equated based on the secret hash.
        write.analysis(path, _analysis("u1"), [_secret_scan(line_hash="abc:1")])
        write.analysis(path, _analysis("u2"), [_secret_scan(line_hash="xyz:1")])
        assert len(read.issues(path, project_id=1)) == 1
        remembered = _query(
            path, "SELECT name, value FROM issue_fingerprint ORDER BY name"
        )
    # The line hash holds the newer value rather than both values it has had.
    assert remembered == [
        ("primaryLocationLineHash", "xyz:1"),
        ("secretHash", "sha256:abcd"),
    ]


def test_an_sca_advisory_is_matched_on_its_rule_alone() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "history.db")
        write.analysis(
            path, _analysis("u1"), [_sca_scan("CVE-2026-1", "poetry.lock", 12, "a:1")]
        )
        # same rule ID, but everything else is different
        write.analysis(
            path, _analysis("u2"), [_sca_scan("CVE-2026-1", "pyproject.toml", 3, "b:1")]
        )
        write.analysis(
            path, _analysis("u3"), [_sca_scan("CVE-2026-2", "poetry.lock", 12, "a:1")]
        )
        issues = read.issues(path, project_id=1)
    # One advisory throughout, and a different CVE at the first one's exact location
    # is still a separate finding.
    assert len(issues) == 2
    assert (issues[0].first_seen_analysis, issues[0].last_seen_analysis) == (1, 2)
    assert (issues[1].first_seen_analysis, issues[1].last_seen_analysis) == (3, 3)

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the secrets scan (reposcan.scans.secrets)."""

import hashlib
import json
from typing import cast

from reposcan.execution.context import ExecutionContext
from reposcan.execution.process import ExecResult
from reposcan.result import Err, Result
from reposcan.scans import sarif
from reposcan.scans.secrets import SecretsScan


class _FakeContext:
    """A context whose `git rev-parse` says whether the target is a git repository."""

    def __init__(self, is_git_repo: bool) -> None:
        self.is_git_repo = is_git_repo
        self.commands: list[list[str]] = []

    def run(self, command: list[str], **kwargs: object) -> Result[ExecResult]:
        self.commands.append(list(command))
        if not self.is_git_repo:
            return Err("not a git repository")  # rev-parse runs with check
        return ExecResult(0, "", "")


def _build_ctx(is_git_repo: bool = True) -> ExecutionContext:
    return cast(ExecutionContext, _FakeContext(is_git_repo))


# Two trufflehog findings (git and filesystem metadata) plus a non-JSON log line.
_TRUFFLEHOG_OUTPUT = (
    json.dumps(
        {
            "SourceMetadata": {
                "Data": {
                    "Git": {
                        "file": "src/config.py",
                        "line": 10,
                        "commit": "deadbeef",
                    }
                }
            },
            "DetectorName": "AWS",
            "Verified": True,
            "Raw": "AKIAEXAMPLE",
        }
    )
    + "\n"
    + "not json, a progress line trufflehog printed\n"
    + json.dumps(
        {
            "SourceMetadata": {"Data": {"Filesystem": {"file": "/scan/x/.env"}}},
            "DetectorName": "GitHub",
            "Verified": False,
            "Raw": "ghp_example",
        }
    )
    + "\n"
)


def test_invocations_choose_git_or_filesystem_by_mode() -> None:
    history = SecretsScan(mode="history").build_invocations(_build_ctx(), "/scan/acme")[
        0
    ]
    assert history.tool == "trufflehog"
    assert history.args == ["git", "file:///scan/acme", "--json", "--no-update"]
    filesystem = SecretsScan(mode="filesystem").build_invocations(
        _build_ctx(), "/scan/acme"
    )[0]
    assert filesystem.args == ["filesystem", "/scan/acme", "--json", "--no-update"]


def test_auto_mode_uses_history_for_a_git_repo_else_filesystem() -> None:
    git = SecretsScan()  # mode defaults to auto (not chosen)
    fake = _FakeContext(is_git_repo=True)
    invocation = git.build_invocations(cast(ExecutionContext, fake), "/scan/acme")[0]
    assert invocation.args[0] == "git"
    assert fake.commands[0][:2] == ["git", "-C"]  # probed the target

    non_git = SecretsScan().build_invocations(_build_ctx(is_git_repo=False), "/scan/x")[
        0
    ]
    assert non_git.args[0] == "filesystem"


def test_explicit_mode_is_not_overridden_by_auto_detection() -> None:
    # mode was chosen, so a non-git target does not switch it to filesystem
    invocation = SecretsScan(mode="history").build_invocations(
        _build_ctx(is_git_repo=False), "/x"
    )[0]
    assert invocation.args[0] == "git"


def test_history_depth_limits_the_commit_scan_and_filesystem_ignores_it() -> None:
    history = SecretsScan(mode="history", depth=50).build_invocations(
        _build_ctx(), "/scan/acme"
    )[0]
    assert history.args[-2:] == ["--max-depth", "50"]
    # depth is a history-only option; a filesystem scan does not carry it.
    filesystem = SecretsScan(mode="filesystem", depth=50).build_invocations(
        _build_ctx(), "/x"
    )[0]
    assert "--max-depth" not in filesystem.args


def test_create_run_turns_trufflehog_findings_into_sarif() -> None:
    run = SecretsScan().create_run(
        "trufflehog", ExecResult(0, _TRUFFLEHOG_OUTPUT, ""), "/scan/x"
    )
    assert not isinstance(run, Err)
    findings = run.results
    assert len(findings) == 2  # the log line was skipped

    aws, github = findings
    assert aws.rule_id == "AWS" and aws.level == "error"  # verified -> error
    assert aws.line == 10
    assert aws.scanners == ["trufflehog"]  # normalized on ingest
    assert github.rule_id == "GitHub" and github.level == "warning"  # unverified
    assert aws.commit == "deadbeef"
    assert github.commit == ""


def test_create_run_fingerprints_each_finding_by_its_secret() -> None:
    output = (
        json.dumps(
            {
                "SourceMetadata": {"Data": {"Git": {"file": "a.py", "line": 1}}},
                "DetectorName": "AWS",
                "Raw": "AKIAEXAMPLE",
                "RawV2": "AKIAEXAMPLE:secretpart",  # preferred when present
            }
        )
        + "\n"
        + json.dumps(
            {
                "SourceMetadata": {"Data": {"Git": {"file": "b.py", "line": 2}}},
                "DetectorName": "GitHub",
                "Raw": "ghp_example",  # no RawV2 -> Raw is hashed
            }
        )
        + "\n"
    )
    run = SecretsScan().create_run("trufflehog", ExecResult(0, output, ""), "/scan/x")
    assert not isinstance(run, Err)
    aws, github = run.results
    aws_hash = hashlib.sha256(b"AKIAEXAMPLE:secretpart").hexdigest()
    assert aws.result["fingerprints"] == {"secretHash/v1": aws_hash}
    assert github.result["fingerprints"]["secretHash/v1"] == (
        hashlib.sha256(b"ghp_example").hexdigest()
    )
    # the secret hash is a complete fingerprint, not a GitHub partialFingerprint
    assert "partialFingerprints" not in aws.result


def test_merge_runs_combines_findings_across_tool_runs() -> None:
    def one_finding(detector: str) -> str:
        data = {"SourceMetadata": {"Data": {"Git": {"file": "x.py"}}}}
        return json.dumps({**data, "DetectorName": detector}) + "\n"

    scan = SecretsScan()
    runs = [
        scan.create_run("trufflehog", ExecResult(0, one_finding("AWS"), ""), "/scan/x"),
        scan.create_run(
            "trufflehog", ExecResult(0, one_finding("GitHub"), ""), "/scan/x"
        ),
    ]
    assert all(not isinstance(run, Err) for run in runs)
    merged = sarif.merge_runs([run for run in runs if not isinstance(run, Err)])
    assert len(merged.results) == 2  # one from each run

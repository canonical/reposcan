# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the secrets scan (reposcan.scans.secrets)."""

import hashlib
import json
from typing import cast

from reposcan.execution.context import ExecutionContext
from reposcan.execution.process import ExecResult
from reposcan.scans import sarif
from reposcan.scans.secrets import SecretsScan


class _FakeContext:
    """A context whose `git rev-parse` reports the given exit code (0 = a git repo)."""

    def __init__(self, git_dir_exit: int) -> None:
        self.git_dir_exit = git_dir_exit
        self.commands: list[list[str]] = []

    def run(self, command: list[str], **kwargs: object) -> ExecResult:
        self.commands.append(list(command))
        return ExecResult(self.git_dir_exit, "", "")


def _ctx(git_dir_exit: int = 0) -> ExecutionContext:
    return cast(ExecutionContext, _FakeContext(git_dir_exit))


# Two trufflehog findings (git and filesystem metadata) plus a non-JSON log line.
_TRUFFLEHOG_OUTPUT = (
    json.dumps(
        {
            "SourceMetadata": {"Data": {"Git": {"file": "src/config.py", "line": 10}}},
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
    history = SecretsScan(mode="history").invocations(_ctx(), "/scan/acme")[0]
    assert history.tool == "trufflehog"
    assert history.args == ["git", "file:///scan/acme", "--json", "--no-update"]
    filesystem = SecretsScan(mode="filesystem").invocations(_ctx(), "/scan/acme")[0]
    assert filesystem.args == ["filesystem", "/scan/acme", "--json", "--no-update"]


def test_auto_mode_uses_history_for_a_git_repo_else_filesystem() -> None:
    git = SecretsScan()  # mode defaults to auto (not chosen)
    fake = _FakeContext(git_dir_exit=0)  # git rev-parse succeeds -> a git repo
    invocation = git.invocations(cast(ExecutionContext, fake), "/scan/acme")[0]
    assert invocation.args[0] == "git"
    assert fake.commands[0][:2] == ["git", "-C"]  # probed the target

    non_git = SecretsScan().invocations(_ctx(git_dir_exit=128), "/scan/x")[0]
    assert non_git.args[0] == "filesystem"


def test_explicit_mode_is_not_overridden_by_auto_detection() -> None:
    # mode was chosen, so a non-git target does not switch it to filesystem
    invocation = SecretsScan(mode="history").invocations(_ctx(git_dir_exit=128), "/x")[
        0
    ]
    assert invocation.args[0] == "git"


def test_history_depth_limits_the_commit_scan_and_filesystem_ignores_it() -> None:
    history = SecretsScan(mode="history", depth=50).invocations(_ctx(), "/scan/acme")[0]
    assert history.args[-2:] == ["--max-depth", "50"]
    # depth is a history-only option; a filesystem scan does not carry it.
    filesystem = SecretsScan(mode="filesystem", depth=50).invocations(_ctx(), "/x")[0]
    assert "--max-depth" not in filesystem.args


def test_create_run_turns_trufflehog_findings_into_sarif() -> None:
    run = SecretsScan().create_run(
        "trufflehog", ExecResult(0, _TRUFFLEHOG_OUTPUT, ""), "/scan/x"
    )
    findings = run.results()
    assert len(findings) == 2  # the log line was skipped

    aws, github = findings
    assert aws.rule_id == "AWS" and aws.level == "error"  # verified -> error
    assert aws.line == 10
    assert aws.scanners == ["trufflehog"]  # normalized on ingest
    assert github.rule_id == "GitHub" and github.level == "warning"  # unverified


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
    aws, github = run.results()
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
    merged = sarif.merge_runs(runs)
    assert len(merged.results()) == 2  # one from each run

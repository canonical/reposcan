# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the scanned repository's identity and git state."""

from collections.abc import Mapping, Sequence

from repo_scanner.execution.context import RunUser
from repo_scanner.execution.process import ExecResult, Failure
from repo_scanner.scans.repo import (
    ProjectIdentity,
    normalize_origin,
    read_repository_state,
)


class FakeGit:
    """A context answering a canned reply per git subcommand."""

    def __init__(self, replies: dict[str, str]) -> None:
        self.replies = replies

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        user: RunUser | None = None,
        timeout: float | None = None,
        stream_stdout: bool = False,
        stream_stderr: bool = False,
        stdin: str | None = None,
    ) -> ExecResult | Failure:
        key = " ".join(command[1:3])
        if key not in self.replies:
            return ExecResult(1, "", "unknown revision")
        return ExecResult(0, self.replies[key], "")


def _context(replies: dict[str, str]) -> object:
    return FakeGit(replies)


def test_normalize_origin_agrees_across_url_forms() -> None:
    expected = "github.com/canonical/repo-scanner"
    assert normalize_origin("git@github.com:canonical/repo-scanner.git") == expected
    assert normalize_origin("https://github.com/canonical/repo-scanner") == expected
    assert normalize_origin("https://user:token@GitHub.com/canonical/repo-scanner/")
    assert (
        normalize_origin("ssh://git@github.com:22/canonical/repo-scanner") == expected
    )
    assert normalize_origin("") == ""


def test_identity_prefers_the_strongest_signal_both_sides_carry() -> None:
    fork = ProjectIdentity("repo-scanner", root_commit="abc", origin="github.com/a/x")
    upstream = ProjectIdentity(
        "repo-scanner", root_commit="abc", origin="github.com/b/x"
    )
    # Both carry a root commit, so the differing origin is never consulted.
    assert fork.matches(upstream) == (True, "root_commit")

    labelled = ProjectIdentity("repo-scanner", root_commit="abc", label="mine")
    other = ProjectIdentity("repo-scanner", root_commit="abc", label="theirs")
    assert labelled.matches(other) == (False, "label")


def test_a_directory_name_only_settles_it_when_nothing_stronger_exists() -> None:
    one = ProjectIdentity("unpacked")
    two = ProjectIdentity("unpacked")
    assert one.matches(two) == (True, "name")

    repository = ProjectIdentity("unpacked", root_commit="abc")
    # A repository and a like-named directory are not the same thing.
    assert repository.matches(one) == (False, "name")
    assert ProjectIdentity("").matches(ProjectIdentity("")) == (False, "name")


def test_repository_state_reads_the_commit_branch_and_cleanliness() -> None:
    ctx = _context(
        {
            "rev-parse HEAD": "c0ffee\n",
            "rev-parse --abbrev-ref": "main\n",
            "rev-list --max-parents=0": "zzz\naaa\n",
            "remote get-url": "git@github.com:canonical/repo-scanner.git\n",
            "status --porcelain": " M src/x.py\n",
        }
    )
    state = read_repository_state(ctx, "/scan/repo-scanner")  # type: ignore[arg-type]
    assert state.commit_sha == "c0ffee"
    assert state.branch == "main"
    assert state.dirty is True
    assert state.shallow is False  # the pragma reply is absent, so not shallow
    assert state.identity.name == "repo-scanner"
    assert state.identity.root_commit == "aaa,zzz"  # sorted, so order cannot vary
    assert state.identity.origin == "github.com/canonical/repo-scanner"


def test_a_target_that_is_not_a_repository_yields_only_its_directory_name() -> None:
    state = read_repository_state(_context({}), "/scan/unpacked/", label="mine")  # type: ignore[arg-type]
    assert state.commit_sha == ""
    assert state.branch == ""
    assert state.identity == ProjectIdentity("unpacked", label="mine")

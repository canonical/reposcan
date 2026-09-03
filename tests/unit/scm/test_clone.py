# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for local mirrors and worktrees."""

import os
import subprocess
import tempfile

from reposcan.execution.process import Failure
from reposcan.scm import clone


def _git(*args: str, cwd: str) -> None:
    subprocess.run(["git", "-C", cwd, *args], check=True, capture_output=True)


def _mk_repo(directory: str) -> str:
    """Create a one-commit repository to clone, returning its file:// url."""
    path = os.path.join(directory, "origin")
    os.makedirs(path)
    subprocess.run(["git", "init", "-q", path], check=True, capture_output=True)
    _git("config", "user.email", "t@example.com", cwd=path)
    _git("config", "user.name", "t", cwd=path)
    with open(os.path.join(path, "a.txt"), "w", encoding="utf-8") as handle:
        handle.write("one\n")
    _git("add", "-A", cwd=path)
    _git("commit", "-qm", "one", cwd=path)
    return f"file://{path}"


def test_a_repository_is_mirrored_then_updated_in_place() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        local_repo_url = _mk_repo(tmp)
        work = os.path.join(tmp, "work")

        worktree = clone.sync_repository(local_repo_url, work, "acme/demo")
        assert not isinstance(worktree, Failure)
        assert sorted(os.listdir(worktree)) == [".git", "a.txt"]
        mirror = os.path.join(work, clone.MIRROR_DIR, "acme/demo.git")
        assert os.path.isdir(mirror)

        # upstream moves on, and a stray file is left behind by an earlier scan
        origin = local_repo_url.removeprefix("file://")
        with open(os.path.join(origin, "b.txt"), "w", encoding="utf-8") as handle:
            handle.write("two\n")
        _git("add", "-A", cwd=origin)
        _git("commit", "-qm", "two", cwd=origin)
        with open(os.path.join(worktree, "stray.tmp"), "w", encoding="utf-8") as handle:
            handle.write("left over\n")

        assert clone.sync_repository(local_repo_url, work, "acme/demo") == worktree
        assert sorted(os.listdir(worktree)) == [".git", "a.txt", "b.txt"]


def test_an_unreachable_remote_is_a_failure_not_a_raise() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        result = clone.sync_repository(
            f"file://{tmp}/nothing-here", os.path.join(tmp, "work"), "acme/gone"
        )
    assert isinstance(result, Failure) and "git clone failed" in result.reason

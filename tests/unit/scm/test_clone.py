# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for local mirrors and worktrees."""

import os
import subprocess
import tempfile

from reposcan.execution.context import Mount, find_git_mounts
from reposcan.result import is_err
from reposcan.scm import clone
from reposcan.scm.github import Repository


def _git(*args: str, cwd: str) -> None:
    subprocess.run(["git", "-C", cwd, *args], check=True, capture_output=True)


def _create_repo(directory: str) -> str:
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


def _build_repository(url: str, name: str = "acme/demo", size: int = 0) -> Repository:
    return Repository(name, url, "main", size=size)


def test_a_repository_is_mirrored_then_updated_in_place() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        local_repo_url = _create_repo(tmp)
        work = os.path.join(tmp, "work")

        demo = _build_repository(local_repo_url)

        worktree = clone.sync_repository(demo, work)
        assert isinstance(worktree, str)
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

        assert clone.sync_repository(demo, work) == worktree
        assert sorted(os.listdir(worktree)) == [".git", "a.txt", "b.txt"]


def test_a_relative_workspace_path_is_made_absolute() -> None:
    # Regression test: the original implementation ran `worktree add` with the relative
    # path, creating a worktree dir inside the mirror dir
    with tempfile.TemporaryDirectory() as tmp:
        local_repo_url = _create_repo(tmp)
        previous_cwd = os.getcwd()
        os.chdir(tmp)
        try:
            workdir = clone.sync_repository(_build_repository(local_repo_url), "work")
        finally:
            os.chdir(previous_cwd)

        expected_workdir = os.path.join(tmp, "work", clone.WORKTREE_DIR, "acme/demo")
        assert workdir == expected_workdir
        assert sorted(os.listdir(expected_workdir)) == [".git", "a.txt"]


def test_an_empty_repository_is_mirrored_with_nothing_to_check_out() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        origin = os.path.join(tmp, "origin")
        subprocess.run(["git", "init", "-q", origin], check=True, capture_output=True)
        work = os.path.join(tmp, "work")
        empty = _build_repository(f"file://{origin}", "acme/empty")

        assert clone.sync_repository(empty, work) is None
        assert not os.path.exists(os.path.join(work, clone.WORKTREE_DIR, "acme/empty"))
        # a later sync updates the mirror, and it is still empty
        assert clone.sync_repository(empty, work) is None


def test_a_mirror_left_without_commits_is_cloned_again_if_github_has_content() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        url = _create_repo(tmp)
        work = os.path.join(tmp, "work")
        mirror = os.path.join(work, clone.MIRROR_DIR, "acme/demo.git")
        # what a clone killed before it saved its remote leaves behind
        os.makedirs(os.path.dirname(mirror))
        subprocess.run(
            ["git", "init", "-q", "--bare", mirror], check=True, capture_output=True
        )

        # with no size from GitHub, it can't be told apart from an empty repository
        assert clone.sync_repository(_build_repository(url), work) is None
        # but GitHub reporting content gives it away, so it is cloned again
        worktree = clone.sync_repository(_build_repository(url, size=1), work)
        assert isinstance(worktree, str)
        assert sorted(os.listdir(worktree)) == [".git", "a.txt"]


def test_a_mirror_git_cannot_read_is_cloned_again_if_github_has_content() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        url = _create_repo(tmp)
        work = os.path.join(tmp, "work")
        # a folder where the mirror should be, but not a repository git can read
        os.makedirs(os.path.join(work, clone.MIRROR_DIR, "acme/demo.git"))

        worktree = clone.sync_repository(_build_repository(url, size=1), work)
        assert isinstance(worktree, str)
        assert sorted(os.listdir(worktree)) == [".git", "a.txt"]


def test_an_unreachable_remote_is_a_failure_not_a_raise() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        result = clone.sync_repository(
            _build_repository(f"file://{tmp}/nothing-here", "acme/gone"),
            os.path.join(tmp, "work"),
        )
    assert is_err(result) and "git clone failed" in result.msg


def test_a_worktree_needs_its_mirror_mounted_where_its_pointer_leads() -> None:
    # A worktree's .git is a pointer into the mirror, outside the worktree; a scan
    # container must mount the mirror too, or git sees no repository at all.
    with tempfile.TemporaryDirectory() as directory:
        url = _create_repo(directory)
        workspace = os.path.join(directory, "workspace")
        worktree = clone.sync_repository(_build_repository(url, "acme/api"), workspace)
        assert isinstance(worktree, str)
        mirror = os.path.join(workspace, clone.MIRROR_DIR, "acme/api.git")

        # an absolute pointer leads to the mirror's own path, inside or out
        assert find_git_mounts(worktree, "/scan/api") == [Mount(mirror, mirror)]

        # a relative pointer leads to the same place relative to the mount point
        pointer = os.path.join(worktree, ".git")
        private = os.path.join(mirror, "worktrees", "api")
        with open(pointer, "w", encoding="utf-8") as handle:
            handle.write(f"gitdir: {os.path.relpath(private, worktree)}\n")
        inside = os.path.normpath(
            os.path.join("/scan/api", os.path.relpath(mirror, worktree))
        )
        assert find_git_mounts(worktree, "/scan/api") == [Mount(mirror, inside)]

        # a regular checkout holds its own .git: nothing extra to mount
        assert find_git_mounts(os.path.join(directory, "origin"), "/scan/x") == []
        assert find_git_mounts(directory, "/scan/x") == []  # not a repository

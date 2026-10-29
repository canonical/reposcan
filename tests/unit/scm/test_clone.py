# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for local mirrors and worktrees."""

import os
import subprocess
import tempfile

from reposcan.execution.context import Mount, find_git_mounts
from reposcan.result import is_err
from reposcan.scm import clone


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


def test_a_repository_is_mirrored_then_updated_in_place() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        local_repo_url = _create_repo(tmp)
        work = os.path.join(tmp, "work")

        worktree = clone.sync_repository(local_repo_url, work, "acme/demo")
        assert not is_err(worktree)
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


def test_a_relative_workspace_path_is_made_absolute() -> None:
    # Regression test: the original implementation ran `worktree add` with the relative
    # path, creating a worktree dir inside the mirror dir
    with tempfile.TemporaryDirectory() as tmp:
        local_repo_url = _create_repo(tmp)
        previous_cwd = os.getcwd()
        os.chdir(tmp)
        try:
            workdir = clone.sync_repository(local_repo_url, "work", "acme/demo")
        finally:
            os.chdir(previous_cwd)

        expected_workdir = os.path.join(tmp, "work", clone.WORKTREE_DIR, "acme/demo")
        assert workdir == expected_workdir
        assert sorted(os.listdir(expected_workdir)) == [".git", "a.txt"]


def test_an_unreachable_remote_is_a_failure_not_a_raise() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        result = clone.sync_repository(
            f"file://{tmp}/nothing-here", os.path.join(tmp, "work"), "acme/gone"
        )
    assert is_err(result) and "git clone failed" in result.msg


def test_a_worktree_needs_its_mirror_mounted_where_its_pointer_leads() -> None:
    # A worktree's .git is a pointer into the mirror, outside the worktree; a scan
    # container must mount the mirror too, or git sees no repository at all.
    with tempfile.TemporaryDirectory() as directory:
        url = _create_repo(directory)
        workspace = os.path.join(directory, "workspace")
        worktree = clone.sync_repository(url, workspace, "acme/api")
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

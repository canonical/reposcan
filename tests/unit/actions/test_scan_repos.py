# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for `reposcan scan-repos` (reposcan.actions.scan_repos)."""

import os
import subprocess
import tempfile

from reposcan.actions.scan_repos import _is_bare_repository, find_repositories


def test_repositories_are_found_at_any_depth() -> None:
    """Every repository under the directory is found, however deep it is."""
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "one", ".git"))
        os.makedirs(os.path.join(tmp, "acme", "two"))
        # a worktree has a .git file
        with open(os.path.join(tmp, "acme", "two", ".git"), "w") as handle:
            handle.write("gitdir: /elsewhere\n")
        os.makedirs(os.path.join(tmp, "notes"))

        found = find_repositories(tmp)

    assert found == [os.path.join(tmp, "acme", "two"), os.path.join(tmp, "one")]


def test_a_nested_repository_counts_as_part_of_its_parent() -> None:
    """Nested repositories are not returned as distinct repos."""
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "one", ".git"))
        os.makedirs(os.path.join(tmp, "one", "vendor", "two", ".git"))

        found = find_repositories(tmp)

    assert found == [os.path.join(tmp, "one")]


def test_hidden_directories_are_skipped() -> None:
    """Hidden directories, like .cache, aren't searched."""
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, ".cache", "one", ".git"))

        found = find_repositories(tmp)

    assert found == []


def test_a_bare_repository_is_recognised() -> None:
    """A directory made by `git init --bare` counts as a bare repository."""
    with tempfile.TemporaryDirectory() as tmp:
        bare = os.path.join(tmp, "one.git")
        working = os.path.join(tmp, "two")
        subprocess.run(["git", "init", "-q", "--bare", bare], check=True)
        subprocess.run(["git", "init", "-q", working], check=True)

        assert _is_bare_repository(bare)
        assert not _is_bare_repository(working)

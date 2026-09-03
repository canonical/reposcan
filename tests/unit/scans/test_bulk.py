# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the bulk scan driver (reposcan.scans.bulk)."""

import os
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from typing import Any

from reposcan.actions.scan_repos import find_worktrees
from reposcan.execution.process import Failure
from reposcan.scans import bulk
from reposcan.scans.analysis import Analysis
from reposcan.scans.repo import ProjectIdentity, RepositoryState


def _analysis() -> Analysis:
    return Analysis.begin(RepositoryState(identity=ProjectIdentity("acme")))


@contextmanager
def _mocks(
    failures: dict[str, str], recorded: list[str], scanned: list[str]
) -> Iterator[None]:
    """Mock everything a bulk run reaches: image, session, scans, database."""

    def fake_run_analysis(
        session: Any, scans: Sequence[Any], **kwargs: Any
    ) -> Analysis:
        return _analysis()

    def fake_scan_one(path: str, *args: Any, **kwargs: Any) -> Analysis | Failure:
        scanned.append(path)
        if path in failures:
            return Failure(reason=failures[path])
        recorded.append(path)
        return _analysis()

    saved = (bulk.ensure_image, bulk._scan_one, bulk.run_analysis)
    bulk.ensure_image = lambda backend, image: None
    bulk._scan_one = fake_scan_one
    bulk.run_analysis = fake_run_analysis
    try:
        yield
    finally:
        bulk.ensure_image, bulk._scan_one, bulk.run_analysis = saved


def test_one_failing_repository_does_not_abandon_the_rest() -> None:
    recorded: list[str] = []
    scanned: list[str] = []
    with _mocks({"b": "no session"}, recorded, scanned):
        results = bulk.scan_repositories(
            ["a", "b", "c"], ["secrets"], db="x.db", threads=2
        )
    assert sorted(scanned) == ["a", "b", "c"]  # it kept going
    assert sorted(recorded) == ["a", "c"]
    assert sorted(p for p, r in results.items() if isinstance(r, Analysis)) == [
        "a",
        "c",
    ]


def test_an_unresolvable_image_fails_every_repository_without_scanning() -> None:
    # Resolved once up front, so a bad image is one failure to report rather than
    # one per repository discovered halfway through the run.
    scanned: list[str] = []
    saved = bulk.ensure_image
    bulk.ensure_image = lambda backend, image: Failure(reason="no such image")
    try:
        results = bulk.scan_repositories(["a", "b"], ["secrets"], db="x.db")
    finally:
        bulk.ensure_image = saved
    assert scanned == []
    reasons = [r.reason for r in results.values() if isinstance(r, Failure)]
    assert reasons == ["no such image"] * 2


def test_a_worktree_layout_is_discovered_and_anything_else_ignored() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        for owner, name, is_repo in (("acme", "one", True), ("acme", "two", False)):
            path = os.path.join(tmp, "worktrees", owner, name)
            os.makedirs(path)
            if is_repo:
                os.makedirs(os.path.join(path, ".git"))
        assert find_worktrees(tmp) == [os.path.join(tmp, "worktrees/acme/one")]
        assert find_worktrees(os.path.join(tmp, "nothing-here")) == []

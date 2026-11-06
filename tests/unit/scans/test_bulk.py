# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the bulk scan driver (reposcan.scans.bulk)."""

import os
import signal
import subprocess
import tempfile
import threading
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from typing import Any
from unittest.mock import MagicMock

import pytest

from reposcan.db import write as db_write
from reposcan.result import Err, Result, is_err
from reposcan.scans import bulk
from reposcan.scans.analysis import Analysis
from reposcan.scans.repo import ProjectIdentity, RepositoryState


def _build_analysis() -> Analysis:
    return Analysis.begin(RepositoryState(identity=ProjectIdentity("acme")))


@contextmanager
def _mocks(
    failures: dict[str, str], recorded: list[str], scanned: list[str]
) -> Iterator[None]:
    """Mock everything a bulk run reaches: image, session, scans, database."""

    def fake_run_analysis(
        session: Any, scans: Sequence[Any], **kwargs: Any
    ) -> Analysis:
        return _build_analysis()

    def fake_scan_one(path: str, *args: Any, **kwargs: Any) -> Result[Analysis]:
        scanned.append(path)
        if path in failures:
            return Err(failures[path])
        recorded.append(path)
        return _build_analysis()

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
    assert sorted(p for p, r in results.items() if not is_err(r)) == [
        "a",
        "c",
    ]


def test_an_unresolvable_image_fails_every_repository_without_scanning() -> None:
    # Resolved once up front, so a bad image is one failure to report rather than
    # one per repository discovered halfway through the run.
    scanned: list[str] = []
    saved = bulk.ensure_image
    bulk.ensure_image = lambda backend, image: Err("no such image")
    try:
        results = bulk.scan_repositories(["a", "b"], ["secrets"], db="x.db")
    finally:
        bulk.ensure_image = saved
    assert scanned == []
    reasons = [r.msg for r in results.values() if is_err(r)]
    assert reasons == ["no such image"] * 2


def test_an_interrupt_skips_the_queued_repositories() -> None:
    """An interrupt cancels the scan in progress and any that haven't started."""
    # interrupt at 0.1s, while the first scan (0.6s) is still running
    scan_one = MagicMock(side_effect=lambda *args, **kwargs: time.sleep(0.6))
    interrupt = threading.Timer(0.1, signal.raise_signal, (signal.SIGINT,))

    saved = (bulk.ensure_image, bulk._scan_one)
    bulk.ensure_image = MagicMock(return_value=None)
    bulk._scan_one = scan_one
    try:
        interrupt.start()
        with pytest.raises(KeyboardInterrupt):
            bulk.scan_repositories(["a", "b", "c"], ["secrets"], db="x.db", threads=1)
    finally:
        bulk.ensure_image, bulk._scan_one = saved

    assert scan_one.call_count == 1
    assert scan_one.call_args.kwargs["cancelled"].is_set()


def test_a_cancelled_analysis_is_not_recorded() -> None:
    """A cancelled analysis isn't written to the database."""
    cancelled = threading.Event()
    cancelled.set()
    write_analysis = MagicMock(return_value=None)

    saved = (bulk.start_session, bulk.run_analysis, db_write.write_analysis)
    bulk.start_session = MagicMock()
    bulk.run_analysis = MagicMock(return_value=_build_analysis())
    db_write.write_analysis = write_analysis
    try:
        result = bulk._scan_one(
            "/w/acme/one",
            ["secrets"],
            db="x.db",
            backend=None,
            image=None,
            user=None,
            env=None,
            options={},
            use_ignore_files=True,
            cancelled=cancelled,
        )
    finally:
        bulk.start_session, bulk.run_analysis, db_write.write_analysis = saved

    assert is_err(result)
    write_analysis.assert_not_called()


def test_repositories_are_found_at_any_depth() -> None:
    """Every repository under the directory is found, however deep it is."""
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "one", ".git"))
        os.makedirs(os.path.join(tmp, "acme", "two"))
        # a worktree has a .git file
        with open(os.path.join(tmp, "acme", "two", ".git"), "w") as handle:
            handle.write("gitdir: /elsewhere\n")
        os.makedirs(os.path.join(tmp, "notes"))

        found = bulk.find_repositories(tmp)

    assert found == [os.path.join(tmp, "acme", "two"), os.path.join(tmp, "one")]


def test_a_nested_repository_counts_as_part_of_its_parent() -> None:
    """Nested repositories are not returned as distinct repos."""
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "one", ".git"))
        os.makedirs(os.path.join(tmp, "one", "vendor", "two", ".git"))

        found = bulk.find_repositories(tmp)

    assert found == [os.path.join(tmp, "one")]


def test_hidden_directories_are_skipped() -> None:
    """Hidden directories, like .cache, aren't searched."""
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, ".cache", "one", ".git"))

        found = bulk.find_repositories(tmp)

    assert found == []


def test_a_bare_repository_is_recognised() -> None:
    """A directory made by `git init --bare` counts as a bare repository."""
    with tempfile.TemporaryDirectory() as tmp:
        bare = os.path.join(tmp, "one.git")
        working = os.path.join(tmp, "two")
        subprocess.run(["git", "init", "-q", "--bare", bare], check=True)
        subprocess.run(["git", "init", "-q", working], check=True)

        assert bulk._is_bare_repository(bare)
        assert not bulk._is_bare_repository(working)

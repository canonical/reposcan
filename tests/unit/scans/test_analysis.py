# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the analysis record (reposcan.scans.analysis)."""

from reposcan.scans.analysis import Analysis, ScanStatus
from reposcan.scans.repo import ProjectIdentity, RepositoryState

_STATE = RepositoryState(identity=ProjectIdentity("acme"))


def test_closing_derives_the_status_from_the_scans_that_failed() -> None:
    with Analysis.begin(_STATE) as clean:
        pass
    assert clean.status is ScanStatus.COMPLETE

    with Analysis.begin(_STATE) as none_survived:
        none_survived.fail("sast")
    assert none_survived.status is ScanStatus.FAILED
    assert none_survived.failed_scans == ["sast"]
    assert none_survived.successful_scans == []

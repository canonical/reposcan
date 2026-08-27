# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Test a JSON --> db --> JSON round trip.

Unlike the synthetic round-trip in the unit tests, these exercise the database against
the real, full-size tool outputs under `fixtures/`: a SARIF document (`sast.json`) and
a CycloneDX SBOM (`sbom.json`). Recording each and reading it back must reproduce the
document it was given.
"""

import os
import tempfile

from repo_scanner.db import read, write
from repo_scanner.db.model import AnalysisRecord, ScanRecord, ScanStatus
from repo_scanner.scans import cyclonedx, sarif
from repo_scanner.scans.model import Artifact, ArtifactKind
from repo_scanner.scans.repo import ProjectIdentity, RepositoryState

_FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _read_fixture(name: str) -> str:
    with open(os.path.join(_FIXTURES, name), encoding="utf-8") as handle:
        return handle.read()


def _round_trip(scan: ScanRecord) -> list[Artifact]:
    """Record `scan` into a fresh database and read its artifacts back."""
    analysis = AnalysisRecord(
        uuid="fixture-analysis",
        started_at="2026-08-24T10:00:00Z",
        finished_at="2026-08-24T10:05:00Z",
        reposcan_version="0.0.0",
        repository=RepositoryState(identity=ProjectIdentity("fixtures")),
    )
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "history.db")
        assert write.analysis(path, analysis, [scan]) is None
        return read.artifacts(path)


def test_sarif_round_trip() -> None:
    document = sarif.parse(_read_fixture("sast.json"))
    assert document is not None
    (run,) = document.runs()
    assert [inv.tool for inv in run.tool_invocations] == ["semgrep"]
    (restored,) = _round_trip(
        ScanRecord(
            category="sast",
            kind=ArtifactKind.SARIF,
            started_at="2026-08-24T10:00:00Z",
            finished_at="2026-08-24T10:01:00Z",
            status=ScanStatus.COMPLETE,
            produced=run,
        )
    )
    expected = sarif.SarifDocument.from_runs([run]).to_dict()
    assert restored.to_dict() == expected
    # Not a vacuous comparison: the fixture carries real findings.
    assert expected["runs"][0]["results"]


def test_cyclonedx_round_trip() -> None:
    document = cyclonedx.parse(_read_fixture("sbom.json"))
    assert document is not None
    assert [inv.tool for inv in document.tool_invocations] == [
        "trivy",
        "syft",
        "cdxgen",
    ]
    (restored,) = _round_trip(
        ScanRecord(
            category="sbom",
            kind=ArtifactKind.CYCLONEDX,
            started_at="2026-08-24T10:02:00Z",
            finished_at="2026-08-24T10:03:00Z",
            status=ScanStatus.COMPLETE,
            produced=document,
        )
    )
    expected = document.to_dict()
    assert restored.to_dict() == expected
    assert len(expected["components"]) == 27  # the fixture is a real inventory

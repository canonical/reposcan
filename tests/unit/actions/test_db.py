# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for `reposcan db import`: its wiring and exit codes."""

import os
import tempfile
from pathlib import Path

from reposcan.app import main
from reposcan.db import read, write
from reposcan.scans.analysis import Analysis, ScanRecord, ScanStatus
from reposcan.scans.model import ArtifactKind
from tests.unit.actions.helpers import FAKE_REPOSITORY, build_sarif_run


def _write_source(path: str) -> None:
    """Record one analysis with one secrets finding, its raw value retained."""
    run = build_sarif_run(1)
    run.results[0].set_secret("RAWSECRETEXAMPLE")
    run.set_automation_id("reposcan/secrets/")
    analysis = Analysis(
        uuid="u1",
        started_at="2026-10-01T10:00:00Z",
        finished_at="2026-10-01T10:01:00Z",
        reposcan_version="0.2.0",
        repository=FAKE_REPOSITORY,
    )
    analysis.add(
        ScanRecord(
            category="secrets",
            kind=ArtifactKind.SARIF,
            started_at="2026-10-01T10:00:00Z",
            finished_at="2026-10-01T10:01:00Z",
            status=ScanStatus.COMPLETE,
            produced=run,
        )
    )
    assert write.write_analysis(path, analysis) is None


def test_retain_secrets_decides_whether_raw_secrets_are_imported() -> None:
    with tempfile.TemporaryDirectory() as directory:
        source = os.path.join(directory, "source.db")
        _write_source(source)
        imported_secrets = []
        for flags in ([], ["--retain-secrets"]):
            destination = os.path.join(directory, f"destination-{len(flags)}.db")
            argv = ["db", "import", source, "--db", destination, "--produced-by", "ci"]
            assert main([*argv, *flags]) == 0
            (artifact,) = read.list_artifacts(destination)
            (imported,) = artifact.to_dict()["runs"][0]["results"]
            imported_secrets.append(imported["properties"].get("reposcan:secret"))
    assert imported_secrets == [None, "RAWSECRETEXAMPLE"]


def test_import_exits_2_for_a_wrong_command_and_1_for_an_unusable_database() -> None:
    with tempfile.TemporaryDirectory() as directory:
        source = os.path.join(directory, "source.db")
        _write_source(source)
        destination = os.path.join(directory, "destination.db")
        text = os.path.join(directory, "notes.txt")
        Path(text).write_text("not a database")
        missing = os.path.join(directory, "missing.db")
        wrong_commands = [
            ["db", "import", missing, "--db", destination, "--produced-by", "ci"],
            ["db", "import", source, "--db", source, "--produced-by", "ci"],
            ["db", "import", source, "--db", destination, "--produced-by", " "],
            ["db", "import", source, "--db", destination],
        ]
        for argv in wrong_commands:
            assert main(argv) == 2, argv
        unusable_db = ["db", "import", source, "--db", text, "--produced-by", "ci"]
        assert main(unusable_db) == 1
        assert not os.path.exists(destination)
        assert Path(text).read_text() == "not a database"

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Test the database with a real scan.

This plants a real repository, runs `reposcan scan` against it in the
real tool image, and checks what the command wrote (a SARIF report on disk and an
analysis in a database).

Excluded from the default unit run; invoke explicitly:

    tox run -e scans
    OR
    pytest tests/scans/test_database.py -s --log-cli-level=INFO

Fails (never skips) when docker is unavailable.
"""

import json
import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import repo_scanner.actions.scan as scan_cmd
from repo_scanner.actions.scan import FINDINGS_EXIT_CODE
from repo_scanner.db import read
from repo_scanner.db.model import reposcan_version
from tests.scans.shared import load_fixture, require_docker

logger = logging.getLogger(__name__)

_ORIGIN = "git@github.com:acme/planted.git"
_NORMALIZED_ORIGIN = "github.com/acme/planted"


def _plant_git_repository(repo: Path) -> None:
    """Make `repo` a git repository with one commit and a remote.

    The scan reads its own repository state, so the state has to be real: a commit to
    record the analysis against, and a remote to identify the project by.
    """
    git = ["git", "-c", "user.name=reposcan", "-c", "user.email=reposcan@example.com"]
    for command in (
        ["init", "-q", "-b", "main"],
        ["remote", "add", "origin", _ORIGIN],
        ["add", "-A"],
        ["commit", "-qm", "planted"],
    ):
        result = subprocess.run(
            [*git, *command], cwd=repo, capture_output=True, text=True
        )
        assert result.returncode == 0, f"git {command[0]}: {result.stderr}"


def test_a_real_scan_is_recorded_and_reads_back() -> None:
    require_docker()
    fixture = load_fixture("sast")

    with tempfile.TemporaryDirectory() as directory:
        repo = Path(directory) / "planted"
        repo.mkdir()
        fixture.plant(repo)
        _plant_git_repository(repo)
        database = os.path.join(directory, "history.db")
        report = os.path.join(directory, "report.sarif")

        logger.info("[docker] scanning the planted repository")
        code = scan_cmd.ScanCommand(
            scans=[fixture.SCAN.name],
            path=str(repo),
            output=report,
            db=database,
            image="build",
        ).run()
        assert code == FINDINGS_EXIT_CODE, f"expected findings, got exit {code}"

        with open(report, encoding="utf-8") as handle:
            emitted = json.load(handle)

        # --- verify the git state read by the scan matches the planted git state
        (project,) = read.projects(database)
        assert project.name == "planted"
        assert project.origin == _NORMALIZED_ORIGIN
        assert project.root_commit  # a real commit, whatever its sha
        (analysis,) = read.analyses(database)
        assert analysis.branch == "main"
        assert analysis.commit_sha == project.root_commit  # the only commit planted
        assert analysis.categories == (fixture.SCAN.name,)
        assert analysis.dirty is False

        # --- verify semgrep findings were added to db
        issues = read.issues(database, project.project_id)
        found = {issue.rule.split(".")[-1] for issue in issues}
        assert {"subprocess-shell-true", "eval-detected"} <= found, sorted(found)
        for issue in issues:
            assert issue.category == fixture.SCAN.name
            assert (issue.first_seen_analysis, issue.last_seen_analysis) == (1, 1)

        # --- verify the emitted report includes analysis metadata
        (emitted_run,) = emitted["runs"]
        assert emitted_run["automationDetails"]["correlationGuid"] == analysis.uuid
        driver = emitted_run["tool"]["driver"]
        assert driver["name"] == "reposcan"
        assert driver["version"] == reposcan_version()
        assert driver["rules"]
        assert emitted_run["versionControlProvenance"] == [
            {
                "repositoryUri": _NORMALIZED_ORIGIN,
                "revisionId": analysis.commit_sha,
                "branch": "main",
            }
        ]
        # --- verify tools produced findgerprints
        for result in emitted_run["results"]:
            assert result["partialFingerprints"]["primaryLocationLineHash"]

        # --- verify database round-trip
        (restored,) = read.artifacts(database)
        assert restored.to_dict() == emitted


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)
    test_a_real_scan_is_recorded_and_reads_back()
    logger.info("passed")

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""CI/workflow scan fixture: a GitHub Actions workflow zizmor flags."""

import subprocess
from pathlib import Path

from reposcan.scans import sarif
from reposcan.scans.workflow import WorkflowScan

SCAN = WorkflowScan()


def plant(repo: Path) -> None:
    # An unpinned action and a template injection into run:, which zizmor flags.
    # Committed because poutine analyses a git repository.
    workflows = repo / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "on: pull_request_target\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: echo ${{ github.event.pull_request.title }}\n"
    )
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "add", "-A")
    _git(
        repo,
        "-c",
        "user.email=f@example.com",
        "-c",
        "user.name=f",
        "commit",
        "-qm",
        "x",
    )


def verify(artifact: sarif.SarifDocument) -> None:
    # zizmor flags this workflow's pull_request_target trigger (dangerous-triggers)
    # and the ${{ github.event.pull_request.title }} injection (template-injection),
    # both in the planted workflow file. poutine may contribute further findings.
    by_rule = {result.rule_id: result for result in artifact.results()}
    for rule in ("zizmor/template-injection", "zizmor/dangerous-triggers"):
        assert rule in by_rule, f"expected {rule}, got {sorted(by_rule)}"
        finding = by_rule[rule]
        assert finding.uri.endswith("ci.yml"), finding.uri
        assert "zizmor" in finding.scanners


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)

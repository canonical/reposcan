# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""SAST scan fixture: Python that semgrep's default rules flag."""

from pathlib import Path

from repo_scanner.scans import sarif
from repo_scanner.scans.sast import SastScan

SCAN = SastScan()


def plant(repo: Path) -> None:
    # A shell=True subprocess and eval(), both caught by semgrep's default rules.
    (repo / "app.py").write_text(
        "import subprocess\n"
        "\n"
        "def run(cmd):\n"
        "    return subprocess.call(cmd, shell=True)\n"
        "\n"
        "def evaluate(expr):\n"
        "    return eval(expr)\n"
    )


def verify(artifact: sarif.SarifDocument) -> None:
    # semgrep flags the shell=True subprocess call (subprocess-shell-true) and the
    # eval() (eval-detected), both in the planted app.py. The rule id is a dotted
    # path ending in the rule's short name.
    by_name = {result.rule_id.split(".")[-1]: result for result in artifact.results()}
    for name in ("subprocess-shell-true", "eval-detected"):
        assert name in by_name, f"expected {name}, got {sorted(by_name)}"
        assert by_name[name].uri.endswith("app.py"), by_name[name].uri

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The IaC scan: infrastructure-as-code checks with checkov.

checkov only writes SARIF to a file, never stdout, so this scan takes its JSON
report on stdout (`-o json`) and converts each failed check into a SARIF result.
`--soft-fail` makes it exit 0 even when checks fail, so a non-zero exit means a
real error rather than findings.
"""

import json

from repo_scanner.execution.context import ExecutionContext
from repo_scanner.execution.process import ExecResult, Failure
from repo_scanner.scans import sarif
from repo_scanner.scans.base import SecurityScan
from repo_scanner.scans.model import ToolInvocation
from repo_scanner.tools.registry import TOOLS


class IacScan(SecurityScan):
    """Scan a repository's infrastructure-as-code for misconfigurations."""

    name = "iac"
    help = "Infrastructure-as-code checks with checkov."

    def invocations(self, ctx: ExecutionContext, target: str) -> list[ToolInvocation]:
        """The single checkov invocation for `target`.

        Args:
            ctx: The started context (unused).
            target: The repository path as seen in the execution context.

        Returns:
            One checkov invocation producing a JSON report on stdout.
        """
        # -o json: checkov's SARIF output only goes to a file, but its JSON report
        # goes to stdout. --quiet drops the banner; --soft-fail exits 0 on findings.
        args = ["-d", target, "-o", "json", "--quiet", "--soft-fail"]
        return [ToolInvocation("checkov", args)]

    def create_run(
        self, tool: str, output: ExecResult, target: str
    ) -> sarif.SarifRun | Failure:
        """Create a SarifRun from command execution output.

        Args:
            tool: The scanner that produced `output` (checkov).
            output: The tool's result (a JSON report on stdout).
            target: The scan root, used to normalize finding uris at ingestion.

        Returns:
            One SARIF run, or a Failure if the output was not JSON.
        """
        run = _checkov_run(output.stdout, target)
        if run is None:
            return Failure(reason=f"{tool} did not produce JSON output")
        return run


def _checkov_run(stdout: str, target: str) -> sarif.SarifRun | None:
    """Convert checkov's JSON report into a SARIF run.

    checkov emits either one report object or, across several frameworks, a list
    of them; each carries `results.failed_checks`. Every failed check becomes a
    SARIF result located at the file and line checkov reported.

    Args:
        stdout: checkov's `-o json` output.
        target: The scan root, used to normalize finding uris at ingestion.

    Returns:
        A SarifRun, or None if `stdout` is not checkov JSON.
    """
    try:
        output = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    reports = output if isinstance(output, list) else [output]
    results = []
    for report in reports:
        if not isinstance(report, dict):
            return None
        for check in report.get("results", {}).get("failed_checks", []):
            rule = str(check.get("check_id", "unknown"))
            message = str(check.get("check_name", rule))
            uri = str(check.get("file_path", "")).lstrip("/")
            line_range = check.get("file_line_range") or [0]
            start = int(line_range[0]) if line_range else 0
            results.append(
                sarif.SarifResult.build(rule, message, uri, start, "checkov", target)
            )
    return sarif.SarifRun.from_results("checkov", TOOLS["checkov"].version, results)

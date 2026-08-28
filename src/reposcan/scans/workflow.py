# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The CI/workflow scan: audit CI/CD definitions with zizmor and poutine.

Both tools emit SARIF; their results are merged into one document, annotated with
which scanner reported each finding (see scans/sarif.py `merge`).
"""

from reposcan.execution.context import ExecutionContext
from reposcan.execution.process import ExecResult, Failure
from reposcan.scans import sarif
from reposcan.scans.base import SecurityScan
from reposcan.scans.model import ToolInvocation
from reposcan.tools.registry import ZIZMOR

# zizmor's exit codes
_ZIZMOR_FINDINGS_EXIT_CODE = 1
_ZIZMOR_NO_INPUTS_EXIT_CODE = 3


class WorkflowScan(SecurityScan):
    """Audit a repository's CI/CD workflow definitions with zizmor and poutine."""

    name = "workflow"
    help = "Audit CI/CD workflows with zizmor and poutine."

    def invocations(self, ctx: ExecutionContext, target: str) -> list[ToolInvocation]:
        """The zizmor and poutine invocations for `target`.

        Args:
            ctx: The started context (unused).
            target: The repository path as seen in the execution context.

        Returns:
            One invocation per tool, each producing SARIF on stdout. `ok_codes`
            allows a findings exit or "no inputs" exit.
        """
        return [
            ToolInvocation(
                "zizmor",
                ["--format", "sarif", target],
                ok_codes=(
                    0,
                    _ZIZMOR_FINDINGS_EXIT_CODE,
                    _ZIZMOR_NO_INPUTS_EXIT_CODE,
                ),
            ),
            ToolInvocation(
                "poutine",
                ["analyze_local", target, "--format", "sarif"],
                ok_codes=(0, 1),
            ),
        ]

    def create_run(
        self, tool: str, output: ExecResult, target: str
    ) -> sarif.SarifRun | Failure:
        """Create a SarifRun from command execution output.

        Args:
            tool: The scanner that produced `output` (zizmor or poutine).
            output: The tool's result (SARIF on stdout).
            target: The scan root, used to normalize finding uris at ingestion.

        Returns:
            The tool's normalized SARIF run, or a Failure if not SARIF.
        """
        if tool == "zizmor" and output.exit_code == _ZIZMOR_NO_INPUTS_EXIT_CODE:
            return sarif.SarifRun.from_results(tool, ZIZMOR.version, [])
        run = sarif.parse_run(output.stdout, tool, target)
        if run is None:
            return Failure(reason=f"{tool} did not produce SARIF output")
        return run

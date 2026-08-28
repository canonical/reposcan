# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The SAST scan: static application security testing with semgrep.

semgrep emits SARIF directly (`--sarif`), so this scan runs it over the target with
its default ruleset and passes the SARIF through as the artifact.
"""

from reposcan.execution.context import ExecutionContext
from reposcan.execution.process import ExecResult, Failure
from reposcan.scans import sarif
from reposcan.scans.base import SecurityScan
from reposcan.scans.model import ToolInvocation


class SastScan(SecurityScan):
    """Scan a repository's source for security issues with semgrep."""

    name = "sast"
    help = "Static analysis of source with semgrep."

    def invocations(self, ctx: ExecutionContext, target: str) -> list[ToolInvocation]:
        """The single semgrep invocation for `target`.

        Args:
            ctx: The started context (unused).
            target: The repository path as seen in the execution context.

        Returns:
            One semgrep invocation producing SARIF on stdout.
        """
        # semgrep's curated default ruleset. `auto` would select rules per detected
        # language but requires metrics to be enabled, so it is not usable with
        # --metrics=off; p/default is the self-contained alternative. No --quiet, so
        # semgrep's scan progress streams live on stderr while the SARIF goes to
        # stdout. ok_codes allows a findings exit since findings are not an error.
        args = [
            "scan",
            "--sarif",
            "--metrics=off",
            "--disable-version-check",
            "--config",
            "p/default",
            target,
        ]
        return [ToolInvocation("semgrep", args, ok_codes=(0, 1))]

    def create_run(
        self, tool: str, output: ExecResult, target: str
    ) -> sarif.SarifRun | Failure:
        """Create a SarifRun from command execution output.

        Args:
            tool: The scanner that produced `output` (semgrep).
            output: The tool's result (SARIF on stdout).
            target: The scan root, used to normalize finding uris at ingestion.

        Returns:
            The tool's normalized SARIF run, or a Failure if not SARIF.
        """
        run = sarif.parse_run(output.stdout, tool, target)
        if run is None:
            return Failure(reason=f"{tool} did not produce SARIF output")
        # remove semgrep's "not logged in" failure; confuses downstream tools with a
        # "hash" that says "requires login"
        for finding in run.results():
            for field in ("fingerprints", "partialFingerprints"):
                entries = finding.result.get(field)
                if not entries:
                    continue
                for name in [
                    name for name, value in entries.items() if value == "requires login"
                ]:
                    del entries[name]
                if not entries:
                    del finding.result[field]
        return run

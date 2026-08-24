# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The SCA scan: software composition analysis with trivy, grype, and govulncheck.

trivy and grype emit SARIF directly; govulncheck emits a JSON message stream, which
is converted to SARIF here. The three are merged into one document, deduped and
annotated with which scanner reported each finding (see scans/sarif.py `merge`).

NOTE: the exact tool flags/output are not verified at build time. govulncheck runs
inside the module (cwd=target) and is optional, so a non-Go repo skips it rather
than failing. The fixture test validates the govulncheck conversion; adjust it if
the message shapes differ.
"""

import json
from typing import Any

from repo_scanner.execution.context import ExecutionContext
from repo_scanner.execution.process import ExecResult, Failure
from repo_scanner.scans import sarif
from repo_scanner.scans.base import DependencyResolvingScan, SecurityScan
from repo_scanner.scans.model import ToolInvocation
from repo_scanner.tools.registry import TOOLS


class ScaScan(SecurityScan, DependencyResolvingScan):
    """Scan a repository's dependencies for known vulnerabilities."""

    name = "sca"
    help = "Dependency vulnerabilities (trivy, grype, govulncheck)."

    def invocations(self, ctx: ExecutionContext, target: str) -> list[ToolInvocation]:
        """The trivy, grype, and govulncheck invocations for `target`.

        Args:
            ctx: The started context (unused).
            target: The repository path as seen in the execution context.

        Returns:
            One invocation per tool. govulncheck runs inside the module and is
            optional (skipped on a non-Go repo); it exits 3 when it finds vulns.
        """
        trivy_args = [
            "fs",
            "--format",
            "sarif",
            "--scanners",
            "vuln",
            "--skip-version-check",
        ]
        if self.include_dev_dependencies:
            trivy_args.append("--include-dev-deps")
        trivy_args.append(target)
        return [
            ToolInvocation("trivy", trivy_args),
            ToolInvocation(
                "grype",
                [f"dir:{target}", "-o", "sarif"],
                env={"GRYPE_CHECK_FOR_APP_UPDATE": "false"},
            ),
            ToolInvocation(
                "govulncheck",
                ["-json", "./..."],
                ok_codes=(0, 3),
                cwd=target,
                optional=True,
            ),
        ]

    def create_run(
        self, tool: str, output: ExecResult, target: str
    ) -> sarif.SarifRun | Failure:
        """Create a SarifRun from command execution output.

        Args:
            tool: The scanner that produced `output`.
            output: The tool's result.
            target: The scan root, used to normalize finding uris at ingestion.

        Returns:
            The tool's normalized SARIF run, or a Failure if not usable.
        """
        if tool == "govulncheck":
            return _govulncheck_run(output.stdout, target)
        run = sarif.parse_run(output.stdout, tool, target)
        if run is None:
            return Failure(reason=f"{tool} did not produce usable output")
        return run


def _govulncheck_position(finding: dict[str, Any]) -> tuple[str, int] | None:
    """The first source position in a govulncheck finding's trace, or None."""
    for frame in finding.get("trace") or []:
        position = frame.get("position")
        if isinstance(position, dict) and position.get("filename"):
            return str(position["filename"]), int(position.get("line") or 0)
    return None


def _govulncheck_run(stdout: str, target: str) -> sarif.SarifRun:
    """Convert govulncheck's JSON message stream into a SARIF run.

    The stream carries OSV vulnerability records and findings. A finding that
    reaches a source position is reported once per OSV id.

    Args:
        stdout: govulncheck's `-json` output.
        target: The scan root, used to normalize finding uris at ingestion.

    Returns:
        A SarifRun (possibly with no results).
    """
    osvs: dict[str, dict[str, Any]] = {}
    findings: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            message = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if not isinstance(message, dict):
            continue
        if isinstance(message.get("osv"), dict):
            entry = message["osv"]
            osvs[str(entry.get("id", ""))] = entry
        elif isinstance(message.get("finding"), dict):
            findings.append(message["finding"])

    results = []
    seen: set[str] = set()
    for finding in findings:
        osv_id = str(finding.get("osv", ""))
        position = _govulncheck_position(finding)
        if position is None or osv_id in seen:
            continue  # report only source-reaching findings, once per vulnerability
        seen.add(osv_id)
        summary = str(osvs.get(osv_id, {}).get("summary") or osv_id)
        results.append(
            sarif.SarifResult.build(
                osv_id, summary, position[0], position[1], "govulncheck", target
            )
        )
    version = TOOLS["govulncheck"].version
    return sarif.SarifRun.from_results("govulncheck", version, results)

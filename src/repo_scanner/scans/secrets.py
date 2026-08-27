# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The secrets scan: find leaked credentials with trufflehog.

trufflehog emits one JSON object per finding (JSONL). This scan runs it over the
target -- the git history by default, or the working-tree files in filesystem mode
-- and turns each finding into a SARIF result.
"""

import hashlib
import json
from typing import Any

from repo_scanner.cli_kit import option
from repo_scanner.execution.context import ExecutionContext
from repo_scanner.execution.process import ExecResult, Failure
from repo_scanner.scans import sarif
from repo_scanner.scans.base import SecurityScan
from repo_scanner.scans.model import ToolInvocation
from repo_scanner.tools.registry import TRUFFLEHOG

# trufflehog flags common to both modes: machine-readable output, no self-update.
_COMMON_ARGS = ["--json", "--no-update"]

# mode default. `invocations` resolves it to "history" for a git repo else "filesystem"
_AUTO = "auto"


class SecretsScan(SecurityScan):
    """Scan a repository for secrets with trufflehog.

    `mode` selects what trufflehog reads: "history" scans the full git history
    (catching secrets later removed); "filesystem" scans only the working tree. When it
    is not chosen, `invocations` picks 'history' for a git repository and 'filesystem'
    otherwise. `depth` limits a history scan to the most recent N commits, or None for
    all; it applies only in history mode.
    """

    name = "secrets"
    help = "Scan for leaked secrets with trufflehog."

    mode: str = option(
        choices=("history", "filesystem"),
        default=_AUTO,
        help="For secrets: scan git history or just the working tree.",
    )
    depth: int | None = option(
        convert=int,
        requires={"mode": "history"},
        help="For secrets history mode: scan only the most recent N commits.",
    )

    def invocations(self, ctx: ExecutionContext, target: str) -> list[ToolInvocation]:
        """The single trufflehog invocation for `target` in the resolved mode.

        Args:
            ctx: The started context, used to detect a git repository.
            target: The repository path as seen in the execution context.

        Returns:
            One trufflehog invocation.
        """
        mode = self.mode
        if self.mode == _AUTO:
            result = ctx.run(["git", "-C", target, "rev-parse", "--git-dir"])
            is_git_repo = not isinstance(result, Failure) and result.exit_code == 0
            mode = "history" if is_git_repo else "filesystem"
        match mode:
            case "filesystem":
                args = ["filesystem", target, *_COMMON_ARGS]
            case "history":
                args = ["git", f"file://{target}", *_COMMON_ARGS]
                if self.depth is not None:
                    args += ["--max-depth", str(self.depth)]
            case _:
                raise ValueError("Unexpected execution mode")
        return [ToolInvocation("trufflehog", args)]

    def create_run(self, tool: str, output: ExecResult, target: str) -> sarif.SarifRun:
        """Create a SarifRun from command execution output.

        Args:
            tool: The scanner that produced `output` (trufflehog).
            output: The tool's result (JSONL findings on stdout).
            target: The scan root, used to normalize finding uris at ingestion.

        Returns:
            One SARIF run listing the findings.
        """
        findings = [
            _to_result(finding, tool, target)
            for finding in _parse_findings(output.stdout)
        ]
        return sarif.SarifRun.from_results(tool, TRUFFLEHOG.version, findings)


def _parse_findings(stdout: str) -> list[dict[str, Any]]:
    """The finding objects in trufflehog's JSONL `stdout`, skipping other lines."""
    findings = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            continue  # progress/log lines that are not findings
        if isinstance(obj, dict) and obj.get("DetectorName"):
            findings.append(obj)
    return findings


def _to_result(finding: dict[str, Any], scanner: str, target: str) -> sarif.SarifResult:
    """Build a SARIF finding from one trufflehog finding."""
    detector = finding.get("DetectorName", "unknown")
    verified = bool(finding.get("Verified"))
    uri, line = _finding_location(finding)
    message = f"{detector} secret detected" + (" (verified)" if verified else "")
    level = "error" if verified else "warning"
    result = sarif.SarifResult.build(
        detector, message, uri, line, scanner, target, level=level
    )
    # RawV2, where a detector sets it, is a more complete/unique form than Raw.
    secret = finding.get("RawV2") or finding.get("Raw") or ""
    if secret:
        digest = hashlib.sha256(secret.encode("utf-8", "surrogatepass")).hexdigest()
        # use sarif's 'name/vN' convention
        result.add_fingerprint("secretHash/v1", digest)
    return result


def _finding_location(finding: dict[str, Any]) -> tuple[str, int]:
    """The (file, line) of a finding, from whichever source metadata carries it."""
    data = finding.get("SourceMetadata", {}).get("Data", {})
    if isinstance(data, dict):
        for value in data.values():  # e.g. Git or Filesystem
            if isinstance(value, dict) and value.get("file"):
                return str(value["file"]), int(value.get("line") or 0)
    return "", 0

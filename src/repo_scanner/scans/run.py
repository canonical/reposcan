# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The scan driver: run a scan against a target and consolidate its tools' outputs.

`run_scan` is backend-agnostic: given a started context, it resolves the dependency
tree (for scans that need it), runs each of the scan's invocations, records provenance,
runs `scan.parse` for each tool's output, and `scan.consolidate` to produce a single
`Artifact`.
"""

from __future__ import annotations

import logging
from dataclasses import asdict
from typing import TYPE_CHECKING

from repo_scanner.execution.context import ExecutionContext, read_file
from repo_scanner.execution.process import ExecResult, Failure
from repo_scanner.scans.exclude import IgnoredPaths
from repo_scanner.scans.model import Artifact, ToolInvocationRecord
from repo_scanner.scans.resolve import resolve_dependencies
from repo_scanner.tools.registry import TOOLS

if TYPE_CHECKING:
    from repo_scanner.scans.base import Scan

logger = logging.getLogger(__name__)


def run_scan(
    scan: Scan,
    ctx: ExecutionContext,
    target: str,
    tool_root: str,
    *,
    resolved_parent: str = "",
    stream: bool = False,
) -> Artifact | Failure:
    """Run `scan` against `target` in `ctx` and consolidate its tools' outputs.

    A dependency-resolving scan (sbom/sca) first resolves the dependency tree, scanning
    the resolved target instead. Then each tool is looked up in the registry and run at
    its installed path. A tool that cannot be started, or exits non-zero, aborts the
    scan as a Failure -- a scan sets its tools' flags so a non-zero exit means a real
    error, not findings.

    Args:
        scan: The scan to run.
        ctx: The started context to run the tools in.
        target: The repository path as seen in the context.
        tool_root: Where the tools are installed in the context.
        resolved_parent: The backend's directory to copy the repo under for dependency
            resolution; used only by dependency-resolving scans.
        stream: When True, echo each tool's live progress (its stderr) to the console
            as it runs. Each tool's stdout (its results) is captured but not echoed,
            so streaming never dumps the report to the console.

    Returns:
        The scan's consolidated artifact, or the first Failure encountered.
    """
    if scan.resolves_dependencies:
        target = resolve_dependencies(
            ctx,
            target,
            tool_root,
            resolved_parent,
            allow_code_execution=getattr(scan, "allow_code_execution", False),
        )
    invocations = scan.invocations(target)
    ignored = IgnoredPaths.from_context(ctx, target)
    artifacts: list[Artifact] = []
    provenance: list[ToolInvocationRecord] = []
    for invocation in invocations:
        tool = TOOLS.get(invocation.tool)
        if tool is None:
            return Failure(reason=f"unknown tool: {invocation.tool}")
        executable = tool.installed_path(tool_root)
        cmd = [
            executable,
            *invocation.args,
            *ignored.exclude_flags(invocation.tool),
        ]
        logger.debug("Running scan command:\n%s", " ".join(cmd))
        result = ctx.run(
            cmd,
            cwd=invocation.cwd or target,
            env=invocation.env,
            stream_stdout=False,
            stream_stderr=stream,
        )
        if isinstance(result, Failure):
            if invocation.optional:
                logger.warning("%s did not run: %s", invocation.tool, result.reason)
                continue
            return result
        provenance.append(
            ToolInvocationRecord(
                **asdict(invocation),
                version=tool.version,
                command=tuple(cmd),
                working_directory=invocation.cwd or target,
                environment=dict(invocation.env or {}),
                exit_code=result.exit_code,
                successful=result.exit_code in invocation.ok_codes,
            )
        )
        if result.exit_code not in invocation.ok_codes:
            reason = result.stderr.strip() or f"exit code {result.exit_code}"
            if invocation.optional:
                logger.warning("skipping %s: %s", invocation.tool, reason)
                continue
            return Failure(reason=f"{invocation.tool} failed: {reason}")
        if invocation.output_file is not None:
            content = read_file(
                ctx, invocation.output_file, cwd=invocation.cwd or target
            )
            if content is None:
                note = f"{invocation.tool} wrote no output to {invocation.output_file}"
                if invocation.optional:
                    logger.warning("%s", note)
                    continue
                return Failure(reason=note)
            result = ExecResult(result.exit_code, content, result.stderr)
        parsed = scan.parse(invocation.tool, result, target)
        if isinstance(parsed, Failure):
            if invocation.optional:
                logger.warning("skipping %s: %s", invocation.tool, parsed.reason)
                continue
            return parsed
        artifacts.append(parsed)
    artifact = scan.consolidate(artifacts)
    if isinstance(artifact, Failure):
        return artifact
    num_dropped = ignored.filter_findings(artifact)
    if num_dropped:
        logger.info("dropped %d finding(s) in git-ignored paths", num_dropped)
    artifact.record_invocations(provenance)
    return artifact

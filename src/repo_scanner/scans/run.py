# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Run scans."""

from __future__ import annotations

import logging
from dataclasses import asdict
from typing import TYPE_CHECKING

from repo_scanner.execution.context import ExecutionContext, read_file
from repo_scanner.execution.process import ExecResult, Failure
from repo_scanner.scans import cyclonedx, sarif
from repo_scanner.scans.gitignore import GitIgnore
from repo_scanner.scans.model import ToolInvocation, ToolInvocationRecord
from repo_scanner.scans.resolve import resolve_dependencies
from repo_scanner.tools.registry import TOOLS

if TYPE_CHECKING:
    from repo_scanner.scans.base import Scan, SecurityScan
    from repo_scanner.scans.sbom import SbomScan

logger = logging.getLogger(__name__)

_ToolOutputs = list[tuple[ToolInvocation, ExecResult]]


def _run_tools(
    scan: Scan,
    ctx: ExecutionContext,
    target: str,
    tool_root: str,
    ignored: GitIgnore,
    *,
    stream: bool,
) -> tuple[_ToolOutputs, list[ToolInvocationRecord]] | Failure:
    """Run each of `scan`'s tools against `target`, collecting their outputs.

    Each tool is looked up in the registry and run at its installed path. A tool that
    cannot be started, or exits non-zero, aborts the scan as a Failure -- a scan sets
    its tools' flags so a non-zero exit means a real error, not findings -- unless the
    invocation is optional, in which case it is skipped.

    Args:
        scan: The scan whose invocations to run.
        ctx: The started context to run the tools in.
        target: The (already resolved) path to scan, as seen in the context.
        tool_root: Where the tools are installed in the context.
        ignored: The git-ignored paths, whose tool flags are added to each command.
        stream: When True, echo each tool's live progress (its stderr) to the console.

    Returns:
        The (invocation, output) of each tool that ran, plus provenance records, or the
        first Failure encountered.
    """
    outputs: _ToolOutputs = []
    provenance: list[ToolInvocationRecord] = []
    for invocation in scan.invocations(ctx, target):
        tool = TOOLS.get(invocation.tool)
        if tool is None:
            return Failure(reason=f"unknown tool: {invocation.tool}")
        cmd = [
            tool.installed_path(tool_root),
            *invocation.args,
            *ignored.tool_flags(invocation.tool),
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
        outputs.append((invocation, result))
    return outputs, provenance


def run_scan(
    scan: SecurityScan,
    ctx: ExecutionContext,
    target: str,
    tool_root: str,
    *,
    resolved_parent: str = "",
    stream: bool = False,
) -> sarif.SarifRun | Failure:
    """Run a security `scan` against `target`, returning a consolidated SarifRun.

    Returns:
        The scan's consolidated SARIF run, or the first Failure encountered.
    """
    if scan.resolves_dependencies:
        target = resolve_dependencies(
            ctx,
            target,
            tool_root,
            resolved_parent,
            allow_code_execution=getattr(scan, "allow_code_execution", False),
        )
    ignored = GitIgnore.from_context(ctx, target)
    outcome = _run_tools(scan, ctx, target, tool_root, ignored, stream=stream)
    if isinstance(outcome, Failure):
        return outcome
    outputs, provenance = outcome
    runs: list[sarif.SarifRun] = []
    for invocation, output in outputs:
        created = scan.create_run(invocation.tool, output, target)
        if isinstance(created, Failure):
            if invocation.optional:
                logger.warning("skipping %s: %s", invocation.tool, created.reason)
                continue
            return created
        runs.append(created)
    run = sarif.merge_runs(runs)
    # trailing slash required; otherwise self.name is interpreted as a run id
    run.set_automation_id(f"reposcan/{scan.name}/")
    scan.add_fingerprints(run, ctx, target)
    num_dropped = ignored.drop_ignored(run)
    if num_dropped:
        logger.info("dropped %d finding(s) in git-ignored paths", num_dropped)
    run.record_invocations(provenance)
    return run


def generate_sbom(
    sbom: SbomScan,
    ctx: ExecutionContext,
    target: str,
    tool_root: str,
    *,
    resolved_parent: str = "",
    stream: bool = False,
) -> cyclonedx.CycloneDxDocument | Failure:
    """Generate an SBOM.

    Returns:
        The consolidated CycloneDX SBOM, or the first Failure encountered.
    """
    target = resolve_dependencies(
        ctx,
        target,
        tool_root,
        resolved_parent,
        allow_code_execution=sbom.allow_code_execution,
    )
    ignored = GitIgnore.from_context(ctx, target)
    outcome = _run_tools(sbom, ctx, target, tool_root, ignored, stream=stream)
    if isinstance(outcome, Failure):
        return outcome
    outputs, provenance = outcome
    documents: list[cyclonedx.CycloneDxDocument] = []
    for invocation, output in outputs:
        document = cyclonedx.parse(output.stdout, invocation.tool)
        if document is None:
            if invocation.optional:
                logger.warning("skipping %s: not CycloneDX", invocation.tool)
                continue
            return Failure(reason=f"{invocation.tool} did not produce CycloneDX output")
        documents.append(document)
    merged = cyclonedx.merge(documents)
    merged.record_invocations(provenance)
    return merged

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Drive dependency resolution across every ecosystem before an SBOM/SCA scan.

The SBOM/SCA tools report a full transitive dependency tree only from a committed
lockfile. When the scan has network access, this pre-step runs a package resolver to
generate one. The repo is mounted read-only, so the resolvers run against a writable
copy of it, which becomes the scan target. It is best-effort: any failure (no
network, an unsatisfiable resolve, a missing resolver) leaves that manifest, or the
whole target, unchanged.

Discovery uses one `git ls-files` on the target. Each ecosystem has its own
`Resolver`.
"""

import logging
import os

from reposcan.execution.context import ExecutionContext
from reposcan.execution.process import ExecResult, succeeded
from reposcan.scans.resolve.interfaces import Resolver
from reposcan.scans.resolve.js import JsResolver
from reposcan.scans.resolve.python import PythonResolver

logger = logging.getLogger(__name__)

# One Resolver per ecosystem; each coordinates the ecosystem's package managers.
_RESOLVERS: tuple[Resolver, ...] = (PythonResolver(), JsResolver())


def resolve_dependencies(
    ctx: ExecutionContext,
    target: str,
    tool_root: str,
    resolved_parent: str,
    *,
    allow_code_execution: bool = False,
) -> str:
    """Generate lockfiles for `target` so scanners catalog transitive deps.

    Discovers every tracked manifest, copies `target` into a writable working
    directory, resolves each ecosystem into the copy, and returns that directory as
    the new scan target. Returns `target` unchanged when there is nothing to resolve
    or the copy fails.

    Args:
        ctx: The started context to run the resolvers in.
        target: The (read-only) repository path as seen in the context.
        tool_root: Where the tools are installed in the context.
        resolved_parent: The directory to copy the repo under (from the backend).
        allow_code_execution: Permit building source packages to resolve
            source-only dependencies (runs untrusted code).

    Returns:
        The directory the scan should target.
    """
    logger.info("Attempting to resolve dependencies and create lockfiles")
    tracked = _tracked_files(ctx, target)
    plans = [
        (resolver, directory)
        for resolver in _RESOLVERS
        for directory in resolver.find_roots(tracked)
    ]
    if not plans:
        return target
    # Copy under `resolved_parent` keeping the repo's own name, so scan-output
    # locations read as "<repo>/..." rather than a scratch-dir name.
    dest = f"{resolved_parent}/{os.path.basename(target.rstrip('/'))}"
    if not _copy_repo(ctx, target, dest):
        return target
    for resolver, directory in plans:
        resolver.resolve(
            ctx,
            dest,
            directory,
            tracked[directory],
            tool_root,
            allow_code_execution=allow_code_execution,
        )
    return dest


def _tracked_files(ctx: ExecutionContext, target: str) -> dict[str, set[str]]:
    """Every tracked file under `target`, grouped by directory.

    Uses `git ls-files` so the listing is confined to tracked files and skips
    git-ignored paths. Returns each directory (relative to `target`, "" for its root)
    mapped to the set of file basenames in it; empty for a non-git target.
    """
    result = ctx.run(["git", "-C", target, "ls-files", "-z"])
    if not isinstance(result, ExecResult) or result.exit_code != 0:
        return {}
    grouped: dict[str, set[str]] = {}
    for path in result.stdout.split("\0"):
        if path:
            grouped.setdefault(os.path.dirname(path), set()).add(os.path.basename(path))
    return grouped


def _copy_repo(ctx: ExecutionContext, target: str, dest: str) -> bool:
    # Ensure the parent exists (the local cache dir may not yet) and clear any stale
    # copy (that cache persists across runs, unlike an ephemeral container).
    ctx.run(["mkdir", "-p", os.path.dirname(dest)])
    ctx.run(["rm", "-rf", dest])
    if succeeded(ctx.run(["cp", "-a", target, dest])):
        return True
    logger.warning("dependency resolution skipped: could not copy the repository")
    return False

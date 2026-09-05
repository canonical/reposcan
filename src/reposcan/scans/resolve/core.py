# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Drive dependency resolution across every ecosystem before an SBOM/SCA scan.

The SBOM/SCA tools report a full transitive dependency tree only from a committed
lockfile. When the scan has network access, this pre-step runs a package resolver to
generate one. It is best-effort: any failure (no network, an unsatisfiable resolve, a
missing resolver) leaves that manifest, or the whole target, unchanged.
"""

import hashlib
import logging
import os

from reposcan.execution.context import ExecutionContext
from reposcan.result import get_value, is_err
from reposcan.scans.resolve.interfaces import Resolver
from reposcan.scans.resolve.js import JsResolver
from reposcan.scans.resolve.python import PythonResolver

logger = logging.getLogger(__name__)

# One Resolver per ecosystem; each coordinates the ecosystem's package managers.
_RESOLVERS: tuple[Resolver, ...] = (PythonResolver(), JsResolver())


def resolve_dependencies(
    ctx: ExecutionContext,
    target: str,
    install_dir: str,
    resolution_workdir: str,
    *,
    allow_code_execution: bool = False,
) -> str:
    """Generate lockfiles for `target` so scanners catalog transitive deps.

    Discovers every tracked manifest, copies `target` (which is mounted read-only)
    into a writable working directory, resolves each ecosystem into the copy, and
    returns that directory as the new scan target.

    Args:
        ctx: The started context to run the resolvers in.
        target: The (read-only) repository path as seen in the context.
        install_dir: Where the tools are installed in the context.
        resolution_workdir: The directory to copy the repo under (from the backend).
        allow_code_execution: Permit building source packages to resolve
            source-only dependencies (runs untrusted code).

    Returns:
        The directory the scan should target: the copy, or `target` itself when there
        is nothing to resolve or the copy fails.
    """
    logger.info("Attempting to resolve dependencies and create lockfiles")
    tracked = _list_tracked_files(ctx, target)
    plans = [
        (resolver, directory)
        for resolver in _RESOLVERS
        for directory in resolver.find_roots(tracked)
    ]
    if not plans:
        return target
    # Copy under `resolution_workdir` in a scratch directory keyed to the target,
    # keeping the repo's own name as the last component so scan-output locations read as
    # "<repo>/...". The key separates two repositories of the same name.
    scratch = hashlib.sha256(target.encode()).hexdigest()[:12]
    dest = f"{resolution_workdir}/{scratch}/{os.path.basename(target.rstrip('/'))}"
    if not _copy_repo(ctx, target, dest):
        return target
    for resolver, directory in plans:
        resolver.resolve(
            ctx,
            dest,
            directory,
            tracked[directory],
            install_dir,
            allow_code_execution=allow_code_execution,
        )
    return dest


def _list_tracked_files(ctx: ExecutionContext, target: str) -> dict[str, set[str]]:
    """List every tracked file under `target`, grouped by directory.

    Uses `git ls-files` so the listing is confined to tracked files and skips
    git-ignored paths.

    Returns:
        Each directory (relative to `target`, "" for its root) mapped to the set of
        file basenames in it; empty for a non-git target.
    """
    run = get_value(ctx.run(["git", "-C", target, "ls-files", "-z"], check=True))
    if run is None:
        return {}
    grouped: dict[str, set[str]] = {}
    for path in run.stdout.split("\0"):
        if path:
            grouped.setdefault(os.path.dirname(path), set()).add(os.path.basename(path))
    return grouped


def _copy_repo(ctx: ExecutionContext, target: str, dest: str) -> bool:
    # Ensure the parent exists (the local cache dir may not yet) and clear any stale
    # copy (that cache persists across runs, unlike an ephemeral container).
    ctx.run(["mkdir", "-p", os.path.dirname(dest)])
    ctx.run(["rm", "-rf", dest])
    if not is_err(ctx.run(["cp", "-a", target, dest], check=True)):
        return True
    logger.warning("dependency resolution skipped: could not copy the repository")
    return False

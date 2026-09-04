# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The `reposcan scan-repos` command: scan a workspace of repositories at once."""

import logging
import os

from reposcan.actions.base import Action
from reposcan.cli_kit import option
from reposcan.execution.context import RunUser, get_host_user, resolve_env
from reposcan.scans import bulk
from reposcan.scans.analysis import Analysis
from reposcan.scans.registry import SCANS, parse_scan_names
from reposcan.scm.clone import WORKTREE_DIR

logger = logging.getLogger(__name__)

# One repository per processor. Unlike cloning, a scan may be CPU-heavy.
_DEFAULT_SCAN_THREADS = os.cpu_count() or 1


class ScanRepos(Action):
    """Scan every repository in a workspace, recording each in one database."""

    name = "scan-repos"
    help = "Scan every repository in a workspace."

    scans: list[str] = option(
        convert=parse_scan_names,
        default=tuple(SCANS),
        help="Scan type(s), comma-separated: secrets, sast, iac, workflow, sca, "
        "or all (e.g. sast,secrets).",
    )
    workspace: str = option(
        required=True,
        env_var="REPOSCAN_WORKSPACE",
        help="Directory holding the worktrees to scan, as `gh clone-repos` writes.",
    )
    db: str = option(
        required=True,
        env_var="REPOSCAN_DB",
        help="Record every analysis in the database at FILE, creating it if absent.",
    )
    threads: int = option(
        default=_DEFAULT_SCAN_THREADS,
        convert=int,
        help="Repositories to scan at once (default: one per processor).",
    )

    def run(self) -> int:
        """Scan each repository in the workspace.

        Exit codes:
            0 when every repository was scanned
            1 when any repository or scan failed
            2 when the workspace holds no repositories
        """
        repositories = find_worktrees(self.workspace)
        if not repositories:
            logger.error("no repositories under %s", self.workspace)
            return 2
        logger.info("scanning %d repositories", len(repositories))

        user = get_host_user() if self.uid is None else RunUser(self.uid, self.uid, ())
        results = bulk.scan_repositories(
            repositories,
            self.scans,
            db=self.db,
            backend=self.backend,
            image=self.image,
            user=user,
            env=resolve_env(self.env),
            threads=self.threads,
        )
        analyses = [r for r in results.values() if isinstance(r, Analysis)]
        complete = [a for a in analyses if not a.failed_scans]
        findings = sum(len(run.results) for a in analyses for run in a.sarif_runs)
        logger.info(
            "scanned %d of %d repositories; %d finding(s) recorded in %s",
            len(complete),
            len(results),
            findings,
            self.db,
        )
        return 0 if len(complete) == len(results) else 1


def find_worktrees(workspace: str) -> list[str]:
    """Find the repositories a workspace holds, as `gh clone-repos` lays them out."""
    root = os.path.join(workspace, WORKTREE_DIR)
    found: list[str] = []
    for owner in sorted(os.listdir(root)) if os.path.isdir(root) else []:
        owned = os.path.join(root, owner)
        if not os.path.isdir(owned):
            continue
        found.extend(
            os.path.join(owned, name)
            for name in sorted(os.listdir(owned))
            if os.path.isdir(os.path.join(owned, name, ".git"))
            or os.path.isfile(os.path.join(owned, name, ".git"))
        )
    return found

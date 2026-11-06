# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The `reposcan scan-repos` command: scan every repository under a directory."""

import logging
import os

from reposcan.actions.base import Action
from reposcan.cli_kit import option, positional
from reposcan.execution.context import RunUser, get_host_user, resolve_env
from reposcan.scans import bulk
from reposcan.scans.analysis import Analysis
from reposcan.scans.registry import SCANS, parse_scan_names

logger = logging.getLogger(__name__)

# One repository per processor. Unlike cloning, a scan may be CPU-heavy.
_DEFAULT_SCAN_THREADS = os.cpu_count() or 1


class ScanRepos(Action):
    """Find and scan every repository within a directory."""

    name = "scan-repos"
    help = "Find and scan every git repository within a directory."

    scans: list[str] = option(
        convert=parse_scan_names,
        default=tuple(SCANS),
        help="Scan type(s), comma-separated: secrets, sast, iac, workflow, sca, "
        "or all (e.g. sast,secrets).",
    )
    path: str = positional(help="Directory to search for git repositories.")
    db: str = option(
        required=True,
        help="Record every analysis in the database at FILE, creating it if absent.",
    )
    threads: int = option(
        default=_DEFAULT_SCAN_THREADS,
        convert=int,
        help="Repositories to scan at once (default: one per processor).",
    )

    def run(self) -> int:
        """Find and scan each repository in a directory.

        Exit codes:
            0 when every repository was scanned
            1 when any repository or scan failed
            2 when no repositories were found
        """
        repositories = find_repositories(self.path)
        if not repositories:
            logger.error("no repositories under %s", self.path)
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


def find_repositories(parent_dir: str) -> list[str]:
    """Find the git repositories in `parent_dir`."""
    found: list[str] = []
    for directory, subdirectories, _ in os.walk(parent_dir):
        # os.walk only goes into the directories left in `subdirectories`
        if os.path.exists(os.path.join(directory, ".git")):
            # a worktree or submodule has a .git file rather than a directory
            found.append(directory)
            # a repository inside this one (a submodule, say) stays part of it
            subdirectories.clear()
        elif _is_bare_repository(directory):
            # skip bare repositories
            subdirectories.clear()
        else:
            subdirectories[:] = sorted(
                name for name in subdirectories if not name.startswith(".")
            )
    return found


def _is_bare_repository(directory: str) -> bool:
    """Check whether `directory` is a bare git repository."""
    return (
        os.path.isfile(os.path.join(directory, "HEAD"))
        and os.path.isdir(os.path.join(directory, "objects"))
        and os.path.isdir(os.path.join(directory, "refs"))
    )

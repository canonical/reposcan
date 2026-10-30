# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The `reposcan gh` group."""

import logging
import os
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from types import ModuleType
from typing import TYPE_CHECKING

from reposcan import output
from reposcan.actions.base import Action
from reposcan.cli_kit import Group, flag, option
from reposcan.logging import TRANSIENT
from reposcan.output import DEFAULT_ROW_LIMIT, Format
from reposcan.result import Err, Result, is_err
from reposcan.scm import clone
from reposcan.table import DEFAULT_WRAP_LINES

if TYPE_CHECKING:  # the module needs the service extra; the annotation does not
    from reposcan.scm.github import Repository

logger = logging.getLogger(__name__)

# concurrency benefit is derived from threads blocking on I/O, so thread count is
# decoupled from CPU count.
_DEFAULT_CLONE_THREADS = 5
# pickup attempts for a dropped connection or DNS blip mid-run
_DEFAULT_CLONE_RETRIES = 2


FORMATS = tuple(f.value for f in Format)


class GhAction(Action):
    """Container for shared `gh` methods and options."""

    org: str | None = option(
        env_var="REPOSCAN_GH_ORG", help="The GitHub organization to read."
    )
    enterprise: str | None = option(
        env_var="REPOSCAN_GH_ENTERPRISE",
        help="The GitHub enterprise whose organizations to read. Needs a token.",
    )
    token_file: str | None = option(
        env_var="REPOSCAN_GH_TOKEN_FILE",
        help="Read a GitHub token from FILE, used when REPOSCAN_GH_TOKEN is unset.",
    )

    include_archived: bool = flag(help="Include archived repositories.")
    exclude_forks: bool = flag(
        help="Skip forked repositories, which are included by default."
    )
    exclude: str | None = option(
        help="Skip repositories whose owner/name matches a comma-separated glob."
    )

    def load_github(self) -> "Result[ModuleType]":
        """Import the GitHub client."""
        # Imported here, not at module: `app` imports every action module to build
        # the command tree, and 'requests' is only included with the 'service' extra.
        try:
            from reposcan.scm import github
        except ModuleNotFoundError as exc:
            if exc.name != "requests":
                return Err(f"could not import reposcan.scm.github: {exc}")
            return Err(
                "reading from GitHub needs the 'service' extra: "
                "pipx install 'reposcan[service]'"
            )
        return github

    def discover_repositories(self, token: str) -> "Result[list[Repository]]":
        """Fetch the repositories from `--org` and `--enterprise`, and apply filters."""
        github = self.load_github()
        if is_err(github):
            return github
        discovered = github.list_repositories(
            org=self.org, enterprise=self.enterprise, token=token
        )
        if is_err(discovered):
            return discovered
        selected = github.filter_repositories(
            discovered,
            include_archived=self.include_archived,
            include_forks=not self.exclude_forks,
            exclude=[g.strip() for g in (self.exclude or "").split(",") if g.strip()],
        )
        logger.info("%d of %d repositories selected", len(selected), len(discovered))
        return selected

    def read_token(self) -> Result[str]:
        """Read the GitHub token from the environment or `--token-file`.

        Returns:
            The token, or an empty string when neither source supplies one.
        """
        token = os.environ.get("REPOSCAN_GH_TOKEN", "")
        if token:
            if self.token_file is not None:
                logger.info("REPOSCAN_GH_TOKEN overrode --token-file")
            return token
        if self.token_file is None:
            return ""
        try:
            with open(self.token_file, encoding="utf-8") as handle:
                return handle.read().strip()
        except OSError as exc:
            return Err(f"could not read token file {self.token_file}: {exc}")


class ListGhRepos(GhAction):
    """List the repositories reposcan would scan."""

    name = "list-repos"
    help = "List the repositories of an organization or enterprise."

    output: str | None = option(
        "-o", help="Write every repository to FILE as JSON instead of stdout."
    )
    format: str | None = option("-f", choices=FORMATS, help="Output format.")
    limit: int = option(
        "-n",
        default=DEFAULT_ROW_LIMIT,
        convert=int,
        help="Maximum rows shown in a table.",
    )
    wrap: int = option(
        default=DEFAULT_WRAP_LINES,
        convert=int,
        help="Maximum lines one row in a table may wrap across.",
    )

    def run(self) -> int:
        """List the repositories.

        Exit codes:
            0 on success, even when nothing was selected
            1 when GitHub could not be read, the extra is not installed, or the
              output file could not be written
            2 when neither --org nor --enterprise was given
        """
        if not (self.org or self.enterprise):
            logger.error("requires --org or --enterprise")
            return 2
        token = self.read_token()
        if is_err(token):
            logger.error("%s", token.msg)
            return 1
        selected = self.discover_repositories(token)
        if is_err(selected):
            logger.error("%s", selected.msg)
            return 1

        # A file always takes JSON; --format chooses how stdout looks.
        if self.output is not None or self.format == Format.JSON:
            rows = [asdict(repo) for repo in selected]
            if is_err(err := output.write_json(rows, self.output)):
                logger.error("%s", err.msg)
                return 1
        else:
            output.write_table(
                ["repository", "branch", "size", "clone url"],
                [
                    [
                        repo.full_name,
                        repo.default_branch,
                        output.format_size(repo.size),
                        repo.clone_url,
                    ]
                    for repo in selected
                ],
                limit=self.limit,
                wrap=self.wrap,
            )
        return 0


class CloneGhRepos(GhAction):
    """Mirror GitHub repositories locally."""

    name = "clone-repos"
    help = "Mirror GitHub repositories locally."

    repo: Sequence[str] = option(
        default=(),
        many=True,
        env_var="REPOSCAN_GH_REPO",
        help="An owner/name repository to clone. Repeatable.",
    )
    workspace: str = option(
        required=True,
        help="Working directory to hold mirrors and worktrees.",
    )
    threads: int = option(
        default=_DEFAULT_CLONE_THREADS,
        convert=int,
        help=f"Repositories to clone at once (default {_DEFAULT_CLONE_THREADS}).",
    )
    retries: int = option(
        default=_DEFAULT_CLONE_RETRIES,
        convert=int,
        help="Times to retry the repositories that failed, after the rest are done "
        f"(default {_DEFAULT_CLONE_RETRIES}).",
    )

    def select_repositories(self, token: str) -> "Result[list[Repository]]":
        """List the repositories named by `--repo`, or by `--org` and `--enterprise`."""
        if not self.repo:
            return self.discover_repositories(token)
        if self.org or self.enterprise:
            logger.warning("--repo was provided, ignoring --org and --enterprise")
        github = self.load_github()
        if is_err(github):
            return github
        # Repositories named explicitly are cloned as named: the archived, fork, and
        # --exclude filters apply only to discovery.
        return github.fetch_named_repositories(self.repo, token)

    def run(self) -> int:
        """Mirror each selected repository, updating any already present.

        Exit codes:
            0 when every repository was mirrored
            1 when GitHub could not be read, or any repository failed
            2 when no entity was named
        """
        if not (self.org or self.enterprise or self.repo):
            logger.error("give at least one of --org, --enterprise, or --repo")
            return 2
        token = self.read_token()
        if is_err(token):
            logger.error("%s", token.msg)
            return 1
        selected = self.select_repositories(token)
        if is_err(selected):
            logger.error("%s", selected.msg)
            return 1

        outcomes = self.sync_repositories(selected, token)
        # The failures get another go once everything else is done, rather than
        # straight away, so a blip has had time to pass.
        for attempt in range(1, self.retries + 1):
            failed = [repo for repo, outcome in outcomes.items() if is_err(outcome)]
            if not failed:
                break
            logger.info(
                "retrying %d failed repositories (attempt %d of %d)",
                len(failed),
                attempt,
                self.retries,
            )
            outcomes.update(self.sync_repositories(failed, token))

        errors = {
            repo.full_name: outcome.msg
            for repo, outcome in outcomes.items()
            if is_err(outcome)
        }
        empty = sum(1 for outcome in outcomes.values() if outcome is None)
        # Listed together at the end, so a long run's failures can't scroll out of view
        for name, msg in sorted(errors.items()):
            logger.error("not mirrored: %s: %s", name, msg)
        logger.info(
            "mirrored %d of %d%s",
            len(selected) - len(errors) - empty,
            len(selected),
            f", skipped {empty} empty" if empty else "",
        )
        return 1 if errors else 0

    def sync_repositories(
        self, repositories: "Sequence[Repository]", token: str
    ) -> "dict[Repository, Result[str | None]]":
        """Mirror each of `repositories`.

        Returns:
            Each repository's outcome, as `clone.sync_repository` gives it: the path
            of its worktree, None when it is empty (nothing to scan, not a failure),
            or an Err saying why it failed.
        """
        outcomes: dict[Repository, Result[str | None]] = {}
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            running = {
                pool.submit(clone.sync_repository, repo, self.workspace, token): repo
                for repo in repositories
            }
            for done, future in enumerate(as_completed(running), start=1):
                repo = running[future]
                logger.info(
                    "[%d/%d] %s",
                    done,
                    len(repositories),
                    repo.full_name,
                    extra=TRANSIENT,
                )
                # Don't crash the entire task for one failed repo
                outcome = future.result()
                if is_err(outcome):
                    logger.warning("%s: %s", repo.full_name, outcome.msg)
                elif outcome is None:
                    logger.info("%s: empty repository, nothing to scan", repo.full_name)
                outcomes[repo] = outcome
        return outcomes


class GhGroup(Group):
    name = "gh"
    help = "Interact with GitHub repositories."
    subcommands = (ListGhRepos, CloneGhRepos)

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The `reposcan gh` group."""

import logging
import os
from collections.abc import Sequence
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import asdict
from types import ModuleType
from typing import TYPE_CHECKING

from reposcan import output
from reposcan.actions.base import Action
from reposcan.cli_kit import Group, flag, option
from reposcan.output import DEFAULT_ROW_LIMIT, Format
from reposcan.result import Err, Result, is_err
from reposcan.scm import clone
from reposcan.table import DEFAULT_WRAP_LINES

if TYPE_CHECKING:  # the module needs the service extra; the annotation does not
    from reposcan.scm.github import GithubRepository

logger = logging.getLogger(__name__)

# concurrency benefit is derived from threads blocking on I/O, so thread count is
# decoupled from CPU count.
_DEFAULT_CLONE_THREAD_COUNT = 5
_DEFAULT_CLONE_RETRY_COUNT = 2


FORMATS = tuple(f.value for f in Format)


class GhAction(Action):
    """Container for shared `gh` methods and options."""

    org: str | None = option(
        env_var="REPOSCAN_GH_ORG",
        help="The GitHub organization to read. The token is optional: without one, "
        "only public repositories are read; with one, whatever the token can see.",
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

    def discover_repositories(self, token: str) -> "Result[list[GithubRepository]]":
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
            logger.error("Requires --org or --enterprise")
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
        default=_DEFAULT_CLONE_THREAD_COUNT,
        convert=int,
        help=f"Repositories to clone at once (default {_DEFAULT_CLONE_THREAD_COUNT}).",
    )
    retries: int = option(
        default=_DEFAULT_CLONE_RETRY_COUNT,
        convert=int,
        help="Times to retry the repositories that failed "
        f"(default {_DEFAULT_CLONE_RETRY_COUNT}).",
    )

    def select_repositories(self, token: str) -> "Result[list[GithubRepository]]":
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
            logger.error("Give at least one of --org, --enterprise, or --repo")
            return 2
        token = self.read_token()
        if is_err(token):
            logger.error("%s", token.msg)
            return 1
        selected = self.select_repositories(token)
        if is_err(selected):
            logger.error("%s", selected.msg)
            return 1

        outcomes = sync_repositories(
            selected, self.workspace, token, threads=self.threads, retries=self.retries
        )

        failed = set()
        empty = 0
        for repo, result in outcomes.items():
            if is_err(result):
                failed.add(repo.full_name)
            elif result.empty:
                empty += 1

        if failed:
            logger.error("Mirror failed for %s", ", ".join(failed))
        logger.info(
            "Successfully mirrored %d of %d, %d of which were empty",
            len(selected) - len(failed),
            len(selected),
            empty,
        )

        return 1 if failed else 0


class GhGroup(Group):
    name = "gh"
    help = "Interact with GitHub repositories."
    subcommands = (ListGhRepos, CloneGhRepos)


def sync_repositories(
    repos: "Sequence[GithubRepository]",
    workspace: str,
    token: str,
    *,
    threads: int = _DEFAULT_CLONE_THREAD_COUNT,
    retries: int = _DEFAULT_CLONE_RETRY_COUNT,
) -> "dict[GithubRepository, Result[clone.LocalRepository]]":
    """Mirror (or sync) each of `repos`.

    Returns:
        a mapping of every requested GithubRepository to a LocalRepository or Err.
    """
    outcomes: dict[GithubRepository, Result[clone.LocalRepository]] = {}
    with ThreadPoolExecutor(max_workers=threads) as pool:
        pending = {
            pool.submit(clone.sync_repository, repo, workspace, token): (repo, 0)
            for repo in repos
        }
        while pending:
            done, _ = wait(pending.keys(), return_when=FIRST_COMPLETED)
            for completed_job in done:
                repo, num_attempts = pending.pop(completed_job)
                num_attempts += 1
                result = completed_job.result()

                if is_err(result):
                    if num_attempts < 1 + retries:
                        logger.warning(
                            "Failed to sync %s (attempt %s of %s): %s",
                            repo.full_name,
                            num_attempts,
                            1 + retries,
                            result.msg,
                        )
                        pending[
                            pool.submit(clone.sync_repository, repo, workspace, token)
                        ] = (repo, num_attempts)
                        continue
                    logger.error(
                        "%s, failed final attempt: %s",
                        repo.full_name,
                        result.msg,
                    )

                outcomes[repo] = result
                if (num_synced := len(outcomes)) % 25 == 0:
                    logger.info(
                        "Sync progress: %s of %s repositories complete",
                        num_synced,
                        len(repos),
                    )

    logger.info("Sync progress: %s repositories complete", len(outcomes))
    return outcomes

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The `reposcan gh` group.

`reposcan.scm.github` is imported inside `run` rather than at module scope: it needs
`requests`, which only the `service` extra installs, and `app` imports every action
module to build the command tree.
"""

import logging
import os
from dataclasses import asdict

from reposcan import output
from reposcan.actions.base import Action
from reposcan.cli_kit import Group, flag, option
from reposcan.execution.process import Failure
from reposcan.output import DEFAULT_ROW_LIMIT, Format
from reposcan.table import DEFAULT_WRAP_LINES

logger = logging.getLogger(__name__)

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

    def read_token(self) -> str | Failure:
        """Returns a gh token, if provided by the caller."""
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
            return Failure(reason=f"could not read token file {self.token_file}: {exc}")


class ListGhRepos(GhAction):
    """List the repositories reposcan would scan."""

    name = "list-repos"
    help = "List the repositories of an organization or enterprise."

    include_archived: bool = flag(help="Include archived repositories.")
    exclude_forks: bool = flag(
        help="Skip forked repositories, which are listed by default."
    )
    exclude: str | None = option(
        help="Skip repositories whose owner/name matches a comma-separated glob."
    )
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
            logger.error("give --org, --enterprise, or both")
            return 2
        # Imported here, not at module: `app` imports every action module to build
        # the command tree, and 'requests' is only included with the 'service' extra.
        try:
            from reposcan.scm import github
        except ModuleNotFoundError as exc:
            if exc.name != "requests":
                raise  # a real import bug, not a missing extra
            logger.error(
                "reading from GitHub needs the 'service' extra: "
                "pipx install 'reposcan[service]'"
            )
            return 1

        token = self.read_token()
        if isinstance(token, Failure):
            logger.error("%s", token.reason)
            return 1

        repos = github.list_repositories(
            org=self.org or "", enterprise=self.enterprise or "", token=token
        )
        if isinstance(repos, Failure):
            logger.error("%s", repos.reason)
            return 1
        selected = github.filter_repositories(
            repos,
            include_archived=self.include_archived,
            include_forks=not self.exclude_forks,
            exclude=[g.strip() for g in (self.exclude or "").split(",") if g.strip()],
        )
        logger.info("%d of %d repositories selected", len(selected), len(repos))
        # A file always takes JSON; --format chooses how stdout looks.
        if self.output is not None or self.format == Format.JSON:
            failure = output.write_json(
                [asdict(repo) for repo in selected], self.output
            )
            if isinstance(failure, Failure):
                logger.error("%s", failure.reason)
                return 1
        else:
            output.write_table(
                ["repository", "branch", "clone url"],
                [
                    [repo.full_name, repo.default_branch, repo.clone_url]
                    for repo in selected
                ],
                limit=self.limit,
                wrap=self.wrap,
            )
        return 0


class GhGroup(Group):
    name = "gh"
    help = "Read repositories from GitHub."
    subcommands = (ListGhRepos,)

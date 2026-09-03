# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""reposcan CLI/entrypoint."""

from reposcan.actions.base import Action
from reposcan.actions.bootstrap import BootstrapAction
from reposcan.actions.config import ConfigGroup
from reposcan.actions.exec import ExecAction
from reposcan.actions.gh import GhGroup
from reposcan.actions.image import ImageGroup
from reposcan.actions.render import RenderAction
from reposcan.actions.sbom import SbomCommand
from reposcan.actions.scan import ScanCommand
from reposcan.actions.scan_repos import ScanRepos
from reposcan.actions.tools import ToolsAction
from reposcan.cli_kit import Cli, Group
from reposcan.settings import resolve


class Reposcan(Group):
    name = "reposcan"
    help = "Run security scans against a locally-cloned repository."
    subcommands = (
        ExecAction,
        ToolsAction,
        BootstrapAction,
        RenderAction,
        ImageGroup,
        ConfigGroup,
        ScanCommand,
        ScanRepos,
        SbomCommand,
        GhGroup,
    )


APP = Cli(name="reposcan", root=Reposcan, base=Action, resolve=resolve)


def main(argv: list[str] | None = None) -> int:
    """Run the `reposcan` command line."""
    return APP.run(argv)

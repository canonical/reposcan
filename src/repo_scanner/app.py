# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""reposcan CLI/entrypoint."""

from repo_scanner.actions.base import Action
from repo_scanner.actions.bootstrap import BootstrapAction
from repo_scanner.actions.config import ConfigGroup
from repo_scanner.actions.exec import ExecAction
from repo_scanner.actions.image import ImageGroup
from repo_scanner.actions.render import RenderAction
from repo_scanner.actions.sbom import SbomCommand
from repo_scanner.actions.scan import ScanCommand
from repo_scanner.actions.tools import ToolsAction
from repo_scanner.cli_kit import Cli, Group
from repo_scanner.settings import resolve


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
        SbomCommand,
    )


APP = Cli(name="reposcan", root=Reposcan, base=Action, resolve=resolve)


def main(argv: list[str] | None = None) -> int:
    """The `reposcan` entry point."""
    return APP.run(argv)

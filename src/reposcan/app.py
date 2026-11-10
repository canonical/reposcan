# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""reposcan CLI/entrypoint."""

import logging
import signal

from reposcan.actions.base import Action
from reposcan.actions.bootstrap import BootstrapAction
from reposcan.actions.config import ConfigGroup
from reposcan.actions.exec import ExecAction
from reposcan.actions.gh import GhGroup
from reposcan.actions.image import ImageGroup
from reposcan.actions.render import RenderAction
from reposcan.actions.sbom import SbomCommand
from reposcan.actions.scan import ScanCommand
from reposcan.actions.tools import ToolsAction
from reposcan.cli_kit import Cli, Group
from reposcan.settings import resolve

logger = logging.getLogger(__name__)

# conventional exit code for a process stopped by SIGINT (128 + 2)
_INTERRUPTED_EXIT_CODE = 130


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
        GhGroup,
    )


APP = Cli(name="reposcan", root=Reposcan, base=Action, resolve=resolve)


def main(argv: list[str] | None = None) -> int:
    """Run the `reposcan` command line."""
    # default_int_handler ensures SIGTERM and SIGINT both raise KeyboardInterrupt
    previous_handler = signal.signal(signal.SIGTERM, signal.default_int_handler)
    try:
        return APP.run(argv)
    except KeyboardInterrupt:
        logger.error("reposcan was interrupted")
        return _INTERRUPTED_EXIT_CODE
    finally:
        signal.signal(signal.SIGTERM, previous_handler)

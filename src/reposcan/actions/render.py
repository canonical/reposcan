# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The `reposcan render` action: show a saved report as a table."""

import logging

from reposcan import output
from reposcan.actions.base import Action
from reposcan.cli_kit import option, positional
from reposcan.execution.process import Failure
from reposcan.output import DEFAULT_ROW_LIMIT, Format
from reposcan.scans import cyclonedx, sarif
from reposcan.scans.model import Artifact
from reposcan.table import DEFAULT_WRAP_LINES

logger = logging.getLogger(__name__)


class RenderAction(Action):
    name = "render"
    help = "Render a saved SARIF or CycloneDX report as a table."

    path: str = positional(help="A saved report: SARIF or CycloneDX JSON.")
    limit: int = option(
        extra_flags="-n",
        default=DEFAULT_ROW_LIMIT,
        convert=int,
        help="Maximum rows shown in the table.",
    )
    wrap: int = option(
        default=DEFAULT_WRAP_LINES,
        convert=int,
        help="Maximum lines one row in a table may wrap across.",
    )

    def run(self) -> int:
        return render(self.path, limit=self.limit, wrap=self.wrap)


def render(
    input_path: str,
    *,
    limit: int = DEFAULT_ROW_LIMIT,
    wrap: int = DEFAULT_WRAP_LINES,
) -> int:
    """Render the report at `input_path` as a table on stdout.

    Returns 0 on success; 2 on a bad input or an unrecognized report; 1 if it could not
    be written.
    """
    artifact = _load(input_path)
    if artifact is None:
        return 2
    failure = output.emit(artifact, fmt=Format.TABLE, limit=limit, wrap=wrap)
    if isinstance(failure, Failure):
        logger.error(failure.reason)
        return 1
    return 0


def _load(input_path: str) -> Artifact | None:
    """The artifact at `input_path`, or None on error (logging why)."""
    try:
        with open(input_path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError as exc:
        logger.error("could not read %s: %s", input_path, exc)
        return None
    artifact = sarif.parse(text) or cyclonedx.parse(text)
    if artifact is None:
        logger.error("%s is not a SARIF or CycloneDX report", input_path)
    return artifact

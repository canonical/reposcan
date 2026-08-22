# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The `reposcan render` action: convert a saved report between formats.

Reads a report -- SARIF/CycloneDX JSON, or a reposcan sqlite database -- and renders
it as a table, as JSON, or as a sqlite database.
"""

import logging

from repo_scanner.actions.base import Action
from repo_scanner.cli_kit import option, positional
from repo_scanner.execution.process import Failure
from repo_scanner.ioutil import sqlitedb
from repo_scanner.ioutil.table import DEFAULT_WRAP_LINES
from repo_scanner.scans import cyclonedx, output, reportdb, sarif
from repo_scanner.scans.model import Artifact
from repo_scanner.scans.output import DEFAULT_ROW_LIMIT, Format

logger = logging.getLogger(__name__)

FORMATS = tuple(f.value for f in Format)


class RenderAction(Action):
    name = "render"
    help = "Render a saved report (JSON or sqlite) as a table, JSON, or sqlite."

    path: str = positional(
        help="A saved report: SARIF/CycloneDX JSON or a sqlite database."
    )
    output: str | None = option(
        extra_flags="-o", help="Write to FILE instead of stdout (required for sqlite)."
    )
    format: str | None = option("-f", choices=FORMATS, help="Output format.")
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
        return render(
            self.path,
            fmt=self.format,
            output_path=self.output,
            limit=self.limit,
            wrap=self.wrap,
        )


def render(
    input_path: str,
    *,
    fmt: str | None = None,
    output_path: str | None = None,
    limit: int = DEFAULT_ROW_LIMIT,
    wrap: int = DEFAULT_WRAP_LINES,
) -> int:
    """Render the report at `input_path` in the chosen format.

    Returns 0 on success; 2 on a bad input or an unrecognized report; 1 if it could not
    be written (including a missing or existing sqlite output file).
    """
    artifacts = _load(input_path)
    if not artifacts:
        return 2
    chosen, error = output.choose_format(fmt, output_path)
    if error is not None:
        logger.warning("%s", error)
        return 2
    failure = output.emit_all(
        artifacts, output=output_path, fmt=chosen, limit=limit, wrap=wrap
    )
    if isinstance(failure, Failure):
        logger.error(failure.reason)
        return 1
    return 0


def _load(input_path: str) -> list[Artifact]:
    """The artifacts at `input_path` (sqlite or JSON); empty on error (logging why).

    A JSON report holds one artifact; a sqlite report may hold both a SARIF and a
    CycloneDX document.
    """
    try:
        with open(input_path, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        logger.error("could not read %s: %s", input_path, exc)
        return []
    artifacts: list[Artifact]
    if sqlitedb.is_sqlite(data):
        artifacts = reportdb.read(input_path)
    else:
        text = data.decode("utf-8", "replace")
        artifact = sarif.parse(text) or cyclonedx.parse(text)
        artifacts = [artifact] if artifact is not None else []
    if not artifacts:
        logger.error("%s is not a SARIF, CycloneDX, or sqlite report", input_path)
    return artifacts

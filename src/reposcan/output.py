# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Render and emit a scan's consolidated artifact.

Every scan result reposcan prints goes through here. On stdout the default is a
concise, human-readable table, and `--format json` gives the native JSON instead; a
file always receives the native JSON. `--limit` caps how many rows a table shows.
"""

import json
import logging
import sys
from enum import Enum

from reposcan.execution.process import Failure
from reposcan.scans.model import Artifact
from reposcan.table import DEFAULT_WRAP_LINES, render_table

logger = logging.getLogger(__name__)

# Default maximum number of rows shown in a table.
DEFAULT_ROW_LIMIT = 20


class Format(str, Enum):
    """A way to render a scan artifact for output."""

    TABLE = "table"
    JSON = "json"


def emit(
    artifact: Artifact,
    *,
    output: str | None = None,
    fmt: Format | None = None,
    limit: int = DEFAULT_ROW_LIMIT,
    wrap: int = DEFAULT_WRAP_LINES,
) -> Failure | None:
    """Render `artifact` and write it to `output` (a file) or stdout.

    The format defaults to a table on stdout and the native JSON document in a
    file; `fmt` overrides that. `limit` caps the table's rows (ignored for JSON).

    Args:
        artifact: The consolidated scan result to render.
        output: A file to write to, or None for stdout.
        fmt: The chosen format, or None to use the destination's default.
        limit: The maximum number of rows to show in a table.
        wrap: The most lines a long table cell may wrap across.

    Returns:
        None on success, or a Failure if the output file already exists (it is not
        overwritten) or could not be written.
    """
    chosen = fmt or (Format.JSON if output is not None else Format.TABLE)
    if chosen is Format.JSON:
        text = json.dumps(artifact.to_dict(), indent=2) + "\n"
    else:
        text = _table(artifact, limit, wrap)
    if output is None:
        sys.stdout.write(text)
        return None
    try:
        # Exclusive create ("x"): refuse to overwrite an existing file atomically,
        # with no time-of-check/time-of-use gap between checking and writing.
        with open(output, "x", encoding="utf-8") as handle:
            handle.write(text)
    except FileExistsError:
        return Failure(
            reason=f"output file already exists, refusing to overwrite: {output}"
        )
    except OSError as exc:
        return Failure(reason=f"could not write {output}: {exc}")
    return None


def _table(artifact: Artifact, limit: int, wrap: int) -> str:
    """A concise text table of the artifact's entries, capped at `limit` rows."""
    headers, rows = artifact.rows()
    shown = rows[:limit] if limit >= 0 else rows
    if len(shown) < len(rows):
        logger.info(
            "showing %d of %d results; use --limit or --format json for all",
            len(shown),
            len(rows),
        )
    return render_table(headers, shown, wrap=wrap)

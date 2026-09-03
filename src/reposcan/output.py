# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Output rendering utilities."""

import json
import logging
import sys
from enum import Enum
from typing import Any

from reposcan.execution.process import Failure
from reposcan.table import DEFAULT_WRAP_LINES, render_table

logger = logging.getLogger(__name__)

# Default maximum number of rows shown in a table.
DEFAULT_ROW_LIMIT = 20


class Format(str, Enum):
    """A way to render a scan artifact for output."""

    TABLE = "table"
    JSON = "json"


def write_json(document: Any, output: str | None = None) -> Failure | None:
    """Write `document` as JSON.

    Args:
        document: The JSON-serializable value to write.
        output: A file to write to, or None for stdout.

    Returns:
        None on success, or a Failure if the output file already exists (it is not
        overwritten) or could not be written.
    """
    text = json.dumps(document, indent=2) + "\n"
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


def write_table(
    headers: list[str],
    rows: list[list[str]],
    *,
    limit: int = DEFAULT_ROW_LIMIT,
    wrap: int = DEFAULT_WRAP_LINES,
) -> None:
    """Print a table of `entries` to stdout, capped at `limit` rows.

    Args:
        headers: The column headers.
        rows: One row per entry.
        limit: The maximum number of rows to show; negative shows every row.
        wrap: The most lines a long cell may wrap across.
    """
    shown = rows[:limit] if limit >= 0 else rows
    if len(shown) < len(rows):
        logger.info(
            "showing %d of %d results; use --limit or --format json for all",
            len(shown),
            len(rows),
        )
    sys.stdout.write(render_table(headers, shown, wrap=wrap))

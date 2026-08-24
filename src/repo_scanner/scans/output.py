# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Render and emit a scan's consolidated artifact.

Every scan result reposcan prints goes through here. On stdout the default is a
concise, human-readable table; to a file the format is inferred from the file's suffix
(`choose_format`), or set with `--format`. `--limit` caps how many rows a table shows.
"""

import json
import logging
import sys
from collections.abc import Sequence
from enum import Enum
from pathlib import Path

from repo_scanner.execution.process import Failure
from repo_scanner.ioutil.table import DEFAULT_WRAP_LINES, render_table
from repo_scanner.scans import reportdb
from repo_scanner.scans.model import Artifact, ArtifactKind

logger = logging.getLogger(__name__)

# Default maximum number of rows shown in a table.
DEFAULT_ROW_LIMIT = 20


class Format(str, Enum):
    """A way to render a scan artifact for output."""

    TABLE = "table"
    JSON = "json"
    SQLITE = "sqlite"  # a binary database; must go to a file, not stdout


# File suffixes that name an output format, for inferring --format from -o FILE.
_SUFFIX_FORMATS = {
    ".json": Format.JSON,
    ".sarif": Format.JSON,
    ".sqlite": Format.SQLITE,
    ".sqlite3": Format.SQLITE,
    ".db": Format.SQLITE,
    ".txt": Format.TABLE,
}


def choose_format(
    fmt: str | None, output: str | None
) -> tuple[Format | None, str | None]:
    """The output format to use, or (None, message) if a file's suffix is unrecognized.

    An explicit `fmt` wins. Otherwise, writing to a file infers the format from the
    file's suffix, so an unrecognized suffix is an error the caller can refuse on before
    doing any work. Writing to stdout with no `fmt` returns (None, None), leaving `emit`
    to fall back to a table.
    """
    if fmt is not None:
        return Format(fmt), None
    if output is None:
        return None, None
    chosen = _SUFFIX_FORMATS.get(Path(output).suffix.lower())
    if chosen is not None:
        return chosen, None
    known = ", ".join(sorted(_SUFFIX_FORMATS))
    return None, (
        f"cannot infer the output format from {output!r}: "
        f"pass --format, or name the file with a known suffix ({known})"
    )


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
        overwritten), could not be written, or the sqlite format was requested without
        an output file.
    """
    chosen = fmt or (Format.JSON if output is not None else Format.TABLE)
    if chosen is Format.SQLITE:
        return _emit_sqlite([artifact], output)
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


def unwritable(
    kinds: set[ArtifactKind], fmt: Format | None, output: str | None
) -> str | None:
    """A usage message if artifacts of `kinds` cannot be written as (fmt, output)."""
    if fmt is Format.SQLITE and output is None:
        return "sqlite output must be written to a file (use -o FILE)"
    single_document = output is not None or fmt is Format.JSON
    if len(kinds) > 1 and fmt is not Format.SQLITE and single_document:
        return (
            "SARIF and CycloneDX cannot be merged into a single JSON file; run the "
            "sbom and security scans separately, or use the sqlite output format."
        )
    return None


def emit_all(
    artifacts: Sequence[Artifact],
    *,
    output: str | None = None,
    fmt: Format | None = None,
    limit: int = DEFAULT_ROW_LIMIT,
    wrap: int = DEFAULT_WRAP_LINES,
) -> Failure | None:
    """Render one or more consolidated artifacts to `output` (a file) or stdout.

    for stdout output, each artifact is rendered separately. for file output, a single
    artifact is written as-is; while multiple artifacts (SARIF plus CycloneDX) need the
    sqlite format.

    Args:
        artifacts: The consolidated artifacts to render (at most one per kind).
        output: A file to write to, or None for stdout.
        fmt: The chosen format, or None to use the destination's default.
        limit: The maximum number of rows to show in a table.
        wrap: The most lines a long table cell may wrap across.

    Returns:
        None on success, or a Failure (as `emit`, plus one when the artifacts cannot be
        rendered together as `fmt`/`output` -- see `unwritable`).
    """
    message = unwritable({artifact.kind for artifact in artifacts}, fmt, output)
    if message is not None:
        return Failure(reason=message)
    if output is None:
        for artifact in artifacts:
            failure = emit(artifact, fmt=fmt, limit=limit, wrap=wrap)
            if failure is not None:
                return failure
        return None
    if (fmt or Format.JSON) is Format.SQLITE:
        return _emit_sqlite(artifacts, output)
    return emit(artifacts[0], output=output, fmt=fmt, limit=limit, wrap=wrap)


def _emit_sqlite(artifacts: Sequence[Artifact], output: str | None) -> Failure | None:
    """Write `artifacts` to a sqlite database at `output` (a file, never stdout)."""
    if output is None:
        return Failure(reason="sqlite output must be written to a file (use -o FILE)")
    try:
        # Reserve the path atomically (exclusive create) so an existing file is not
        # overwritten; sqlite then initializes the empty file into a database.
        with open(output, "x"):
            pass
    except FileExistsError:
        return Failure(
            reason=f"output file already exists, refusing to overwrite: {output}"
        )
    except OSError as exc:
        return Failure(reason=f"could not write {output}: {exc}")
    reportdb.write(artifacts, output)
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

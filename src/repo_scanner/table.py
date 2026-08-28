# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Render a concise, terminal-fit text table from headers and rows.

A generic utility with no domain knowledge: it takes column headers and string rows
and produces aligned columns under a dashed header, shrunk to fit the terminal.
"""

import shutil
import textwrap

# The default number of lines a long cell may wrap across.
DEFAULT_WRAP_LINES = 4

# Cap on a single table cell's width; longer text is wrapped or clipped.
_MAX_CELL_WIDTH = 60


def render_table(
    headers: list[str], rows: list[list[str]], *, wrap: int = DEFAULT_WRAP_LINES
) -> str:
    """A concise text table: aligned columns under a dashed header, fit to the terminal.

    `wrap` is the most lines a long cell may span; text beyond that is clipped with an
    ellipsis on the last line. `wrap=1` keeps every cell to a single clipped line.
    """
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], min(len(cell), _MAX_CELL_WIDTH))
    _fit_to_terminal(widths)

    lines = _render_row(headers, widths, wrap=1)  # the header is always one line
    lines.append("  ".join("-" * width for width in widths))
    for row in rows:
        lines.extend(_render_row(row, widths, wrap))
    return "\n".join(lines) + "\n"


def _fit_to_terminal(widths: list[int]) -> None:
    """Shrink the widest columns in place until a row fits the terminal width.

    Columns are separated by two spaces, so a rendered line is `sum(widths)` plus
    two per gap. The widest column is trimmed one char at a time (never below one)
    until the total fits, so no line is ever wider than the terminal.
    """
    gaps = 2 * (len(widths) - 1)
    available = shutil.get_terminal_size(fallback=(80, 24)).columns - gaps
    while sum(widths) > available and any(width > 1 for width in widths):
        widest = max(range(len(widths)), key=lambda index: widths[index])
        widths[widest] -= 1


def _render_row(cells: list[str], widths: list[int], wrap: int) -> list[str]:
    """The physical lines for one row: one line, or several when a cell wraps."""
    columns = [
        _cell_lines(cell, widths[index], wrap) for index, cell in enumerate(cells)
    ]
    height = max((len(column) for column in columns), default=1)
    lines = []
    for line in range(height):
        parts = [
            (column[line] if line < len(column) else "").ljust(widths[index])
            for index, column in enumerate(columns)
        ]
        lines.append("  ".join(parts).rstrip())
    return lines


def _cell_lines(cell: str, width: int, wrap: int) -> list[str]:
    """A cell as up to `wrap` wrapped lines, or one clipped line when `wrap` <= 1."""
    if wrap <= 1:
        return [_clip(cell, width)]
    wrapped = textwrap.wrap(cell, width) or [""]
    if len(wrapped) > wrap:
        wrapped = wrapped[:wrap]
        wrapped[-1] = _clip(wrapped[-1] + " ...", width)
    return wrapped


def _clip(text: str, width: int) -> str:
    """`text` truncated to `width`, with an ellipsis if it was too long."""
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."

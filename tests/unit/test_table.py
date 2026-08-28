# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the generic table renderer (repo_scanner.table)."""

from repo_scanner.table import render_table


def test_columns_align_under_a_dashed_header() -> None:
    out = render_table(["key", "value"], [["backend", "docker"], ["uid", "4000"]])
    lines = out.splitlines()
    assert lines[0] == "key      value"  # header padded to the widest cell per column
    assert lines[1] == "-------  ------"  # a dashed separator sized to each column
    assert lines[2] == "backend  docker"
    assert lines[3] == "uid      4000"


def test_a_long_cell_wraps_by_default_and_clips_past_the_cap() -> None:
    # Wrapping is on by default (4 lines); a cell that overflows it is clipped with an
    # ellipsis on the last line.
    body = render_table(["c"], [["x" * 400]]).splitlines()[2:]
    assert len(body) == 4  # wrapped up to the default cap
    assert body[-1].rstrip().endswith("...")  # overflow past the cap is clipped


def test_wrap_1_keeps_a_long_cell_to_a_single_clipped_line() -> None:
    long = "x" * 200
    table = render_table(["c"], [[long]], wrap=1).splitlines()
    assert len(table) == 3
    row = table[2]
    assert row.endswith("...")
    assert len(row) < len(long)

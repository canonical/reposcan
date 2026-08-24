# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the `reposcan render` action (repo_scanner.actions.render)."""

import io
import json
import os
import tempfile
from contextlib import redirect_stdout

from repo_scanner.actions.render import render
from repo_scanner.ioutil.sqlitedb import is_sqlite
from repo_scanner.scans import sarif


def _write(directory: str, name: str, content: str) -> str:
    path = os.path.join(directory, name)
    with open(path, "w") as handle:
        handle.write(content)
    return path


def _sarif_doc() -> dict:
    run = sarif.SarifRun.from_results(
        "tool",
        "1.0",
        [sarif.SarifResult.build("X", "boom", "a.py", 3, "tool", "", level="error")],
    )
    return sarif.SarifDocument.from_runs([run]).to_dict()


def test_renders_json_input_as_a_table() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = _write(directory, "r.sarif", json.dumps(_sarif_doc()))
        out = io.StringIO()
        with redirect_stdout(out):
            assert render(path) == 0
    text = out.getvalue()
    assert "LEVEL" in text and "X" in text and "a.py:3" in text


def test_round_trips_json_through_sqlite() -> None:
    doc = _sarif_doc()
    with tempfile.TemporaryDirectory() as directory:
        src = _write(directory, "r.sarif", json.dumps(doc))
        db = os.path.join(directory, "r.db")
        assert render(src, fmt="sqlite", output_path=db) == 0

        table = io.StringIO()
        with redirect_stdout(table):
            assert render(db, fmt="table") == 0  # sqlite input -> table
        assert "a.py:3" in table.getvalue()

        rendered = io.StringIO()
        with redirect_stdout(rendered):
            assert render(db, fmt="json") == 0  # sqlite input -> json
        assert json.loads(rendered.getvalue()) == doc  # faithful round-trip


def test_sqlite_output_requires_an_output_file() -> None:
    with tempfile.TemporaryDirectory() as directory:
        src = _write(directory, "r.sarif", json.dumps(_sarif_doc()))
        assert render(src, fmt="sqlite") == 1  # emit fails: no -o FILE


def test_missing_or_unrecognized_input_is_a_usage_error() -> None:
    assert render("/no/such/file.json") == 2
    with tempfile.TemporaryDirectory() as directory:
        path = _write(directory, "junk.txt", "not a report")
        assert render(path) == 2


def test_output_format_is_inferred_from_the_file_suffix() -> None:
    with tempfile.TemporaryDirectory() as directory:
        src = _write(directory, "r.sarif", json.dumps(_sarif_doc()))
        db = os.path.join(directory, "out.sqlite")  # .sqlite, no --format
        assert render(src, output_path=db) == 0
        with open(db, "rb") as handle:
            assert is_sqlite(handle.read())  # inferred sqlite from the suffix


def test_an_unrecognized_output_suffix_is_refused_without_writing() -> None:
    with tempfile.TemporaryDirectory() as directory:
        src = _write(directory, "r.sarif", json.dumps(_sarif_doc()))
        out = os.path.join(directory, "out.weird")  # unknown suffix, no --format
        assert render(src, output_path=out) == 2
        assert not os.path.exists(out)  # nothing was written

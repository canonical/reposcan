# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the `reposcan render` action (repo_scanner.actions.render)."""

import io
import json
import os
import tempfile
from contextlib import redirect_stdout

from repo_scanner.actions.render import render
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
        [
            sarif.SarifResult.build(
                "X", "insecure hash function", "a.py", 3, "tool", "", level="error"
            )
        ],
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


def test_missing_or_unrecognized_input_is_a_usage_error() -> None:
    assert render("/no/such/file.json") == 2
    with tempfile.TemporaryDirectory() as directory:
        path = _write(directory, "junk.txt", "not a report")
        assert render(path) == 2

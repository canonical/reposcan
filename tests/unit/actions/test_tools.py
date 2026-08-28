# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the `reposcan tools` action (reposcan.actions.tools)."""

import io
import os
import tempfile
from contextlib import redirect_stdout

from reposcan.actions.tools import list_tools
from reposcan.tools.registry import TOOLS, TRUFFLEHOG


def test_lists_every_scanning_tool_with_its_install_status() -> None:
    with tempfile.TemporaryDirectory() as root:
        # Mark one tool installed by creating the path `tools` checks for.
        marker = TRUFFLEHOG.installed_path(root)
        os.makedirs(os.path.dirname(marker), exist_ok=True)
        open(marker, "w").close()

        out = io.StringIO()
        with redirect_stdout(out):
            code = list_tools(root)

    assert code == 0
    listing = out.getvalue()
    # Every scanning tool is listed; prerequisites (uv, the Go SDK) are not.
    for name in TOOLS:
        assert name in listing
    lines = {line.split()[0]: line for line in listing.splitlines()}
    assert "uv" not in lines
    assert "go" not in lines
    # The one we created a marker for is installed; the rest are missing.
    assert lines["trufflehog"].split()[-1] == "yes"
    assert lines["semgrep"].split()[-1] == "no"

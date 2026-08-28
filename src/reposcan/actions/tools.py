# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The `reposcan tools` action: list tools and their install status."""

import os
import sys

from reposcan.actions.base import Action
from reposcan.paths import tools_root
from reposcan.table import render_table
from reposcan.tools.registry import TOOLS


class ToolsAction(Action):
    name = "tools"
    help = "List the scanning tools and whether each is installed."

    def run(self) -> int:
        return list_tools(str(tools_root()))


def list_tools(install_root: str) -> int:
    """List every scanning tool with its version, kind, and install status.

    Shows whether each tool is installed under `install_root`. Always returns 0.
    """
    rows = []
    for tool in TOOLS.values():
        installed = os.path.exists(tool.installed_path(install_root))
        on_localhost = "yes" if installed else "no"
        rows.append((tool.name, tool.version, tool.kind.value, on_localhost))

    name_width, version_width, kind_width = 0, 0, 0
    for name, version, kind, _ in rows:
        name_width = max(len(name), name_width)
        version_width = max(len(version), version_width)
        kind_width = max(len(kind), kind_width)

    sys.stdout.write(
        render_table(["name", "version", "kind", "installed on localhost"], rows)
    )
    return 0

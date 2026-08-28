# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the real tool registry (reposcan.tools.registry).

The registry is data, so the high-signal checks are that the user-facing set is right
and that every tool -- including the prerequisites pulled in behind it -- carries real
supply-chain pins and is wired to the right dependency.
"""

from reposcan.tools.install import install_plan
from reposcan.tools.model import GoTool, NativeBinary, Platform, PypiTool
from reposcan.tools.registry import GO_SDK, RESOLVER_TOOLS, TOOLS, UV


def test_every_tool_is_fully_pinned_and_wired_to_its_prerequisite() -> None:
    # install_plan pulls in the prerequisites, so iterating it covers uv and the Go SDK
    # too. Each tool must carry a real pin, and the dependents must name the concrete
    # prerequisite instance.
    everything = [*TOOLS.values(), *RESOLVER_TOOLS]
    for step in install_plan(everything, Platform("linux", "amd64"), "/opt/tools"):
        tool = step.tool
        if isinstance(tool, PypiTool):
            assert "--hash=sha256:" in tool.requirements
            assert tool.requires == (UV,)
        elif isinstance(tool, GoTool):
            assert tool.module_sum.startswith("h1:")
            assert tool.gomod_sum.startswith("h1:")
            assert tool.requires == (GO_SDK,)
        elif isinstance(tool, NativeBinary):
            assert tool.downloads, f"{tool.name} has no downloads"
            for download in tool.downloads:
                assert len(download.sha256) == 64  # a full sha256, not a placeholder
        else:
            raise AssertionError(f"unexpected tool type {type(tool).__name__}")

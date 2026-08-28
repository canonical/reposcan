# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""reposcan tool installation.

`reposcan bootstrap` and image generation consume the same per-tool
`install_commands`. Bootstrap runs each command through an ExecutionContext, so the
same commands install onto the host or into a Docker/LXD container. Image generation
writes them into a build/install script baked into the image. This module is the
single point that orders and groups them, so there is one definition of how each
tool installs.

The commands are grouped per tool (`ToolInstall`) rather than flattened, so each
tool is an independent failure domain: bootstrap runs each group and continues past
a failure, and image generation emits each group as its own build step. Installing
9 of 10 tools beats installing 0.
"""

import os
from collections.abc import Iterable
from dataclasses import dataclass

from reposcan.tools.model import Platform, Tool

# Machine names (os.uname().machine) mapped to the arch tokens the registry uses.
_ARCHES = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}


def current_platform() -> Platform:
    """The host OS/arch, named as the registry's Download entries are.

    An unknown machine is passed through unchanged, so no matching Download is found
    and the install fails loudly rather than picking the wrong artifact.
    """
    uname = os.uname()
    return Platform(
        os=uname.sysname.lower(),
        arch=_ARCHES.get(uname.machine.lower(), uname.machine.lower()),
    )


@dataclass(frozen=True)
class ToolInstall:
    """One tool's install commands, kept as a self-contained group."""

    tool: Tool
    commands: list[str]


def _add_with_requirements(tool: Tool, ordered: list[Tool], seen: set[str]) -> None:
    """Append `tool` to `ordered`, recursively adding its dependencies first.

    Its dependencies, their dependencies, and so on are added before it. `seen` tracks
    names already added, which also breaks any cycle.
    """
    if tool.name in seen:
        return
    seen.add(tool.name)
    for requirement in tool.requires:
        _add_with_requirements(requirement, ordered, seen)
    ordered.append(tool)


def install_plan(
    tools: Iterable[Tool], platform: Platform, install_root: str
) -> list[ToolInstall]:
    """Per-tool install groups for `tools` and everything they require.

    De-duplicated and ordered so each tool is installed after its requirements: uv
    before its PyPI tools, the Go SDK before its Go tools. Requesting `semgrep` alone
    therefore also installs `uv`. Each group installs independently.

    Args:
        tools: The tools to install, before their requirements are added.
        platform: The OS/arch the install commands target.
        install_root: The directory the tools install under.

    Returns:
        One ToolInstall per tool, de-duplicated and ordered so each tool follows its
        requirements.
    """
    ordered: list[Tool] = []
    seen: set[str] = set()
    for tool in tools:
        _add_with_requirements(tool, ordered, seen)
    return [
        ToolInstall(tool, tool.install_commands(platform, install_root))
        for tool in ordered
    ]

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The `reposcan bootstrap` action: install tools onto the host or a container.

With an explicit --backend, install into a container. All scanning tools by
default, or a named subset; either way each tool's prerequisites (uv, the Go SDK)
are pulled in automatically.
"""

import logging
import sys

from reposcan.actions.base import Action
from reposcan.backends import start_session
from reposcan.cli_kit import flag, positional
from reposcan.execution.context import ExecutionContext
from reposcan.execution.process import Failure
from reposcan.tools.install import current_platform, install_plan
from reposcan.tools.model import Platform, Tool
from reposcan.tools.registry import TOOLS

logger = logging.getLogger(__name__)


class BootstrapAction(Action):
    name = "bootstrap"
    help = "Install tools onto the host. Runs locally unless --backend is given."

    tools: list[str] = positional(
        many=True,
        help="Tools to install; prerequisites are added. Empty installs every tool.",
    )
    confirm: bool = flag(help="Skip interactive confirmation before installing tools.")

    def run(self) -> int:
        backend = self.backend if self.backend != "auto" else "local"
        with start_session(backend, tool_image=False, image=self.image) as session:
            if not session.ok:
                return session.exit_code
            if (
                session.context.name == "local"
                and not self.confirm
                and not _confirm_host_install()
            ):
                return 1
            return bootstrap(
                session.context, self.tools, current_platform(), session.tool_root
            )


def bootstrap(
    ctx: ExecutionContext, names: list[str], platform: Platform, install_root: str
) -> int:
    """Install `names` (an empty list means every scanning tool).

    Adds the prerequisites each depends on. Tools install as independent groups: if one
    fails it is reported and the rest proceed. Returns 0 when every tool installed, 1 if
    any failed, or 2 for an unknown tool name.
    """
    if names:
        requested: list[Tool] = []
        unknown = []
        for name in names:
            tool = TOOLS.get(name)
            if tool is None:
                unknown.append(name)
            else:
                requested.append(tool)
        if unknown:
            logger.error("unknown tool(s): %s", ", ".join(unknown))
            return 2
    else:
        requested = list(TOOLS.values())

    plan = install_plan(requested, platform, install_root)
    failed = []
    for step in plan:
        logger.info("installing %s %s", step.tool.name, step.tool.version)
        reason = None
        for command in step.commands:
            # Feed the script on stdin, not as a `-c` argument: a hash-pinned lock
            # embedded in the command can exceed the kernel's per-argument size limit.
            result = ctx.run(["sh", "-eu"], stdin=command)
            if isinstance(result, Failure):
                reason = result.reason
                break
            if not result.ok:
                reason = result.stderr.strip() or f"exit code {result.exit_code}"
                break
        if reason is not None:
            logger.error("failed to install %s: %s", step.tool.name, reason)
            failed.append(step.tool.name)

    if failed:
        logger.error(
            "%d of %d tools failed: %s", len(failed), len(plan), ", ".join(failed)
        )
        return 1
    logger.info("installed %d tools into %s", len(plan), install_root)
    return 0


def _confirm_host_install() -> bool:
    """Confirm whether to install the scanning tools directly onto this host."""
    sys.stderr.write(
        "'bootstrap' installs the scanning tools directly onto this host.\n"
        "reposcan normally runs the tools inside an ephemeral container, so this is\n"
        "not the usual path and it changes this system.\n"
    )
    if not sys.stdin.isatty():
        logger.error(
            "cannot ask for confirmation on a non-interactive terminal; re-run with "
            "--confirm to install the tools on the host"
        )
        return False
    sys.stderr.write("Install the tools on this host anyway? [y/N] ")
    sys.stderr.flush()
    try:
        reply = input()
    except EOFError:
        return False
    return reply.strip().lower() in ("y", "yes")

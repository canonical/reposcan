# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The `reposcan exec` action: run a command in the selected execution context."""

import logging
import sys

from reposcan.actions.base import Action
from reposcan.backends import start_session
from reposcan.cli_kit import option, remainder
from reposcan.execution.context import ExecutionContext
from reposcan.execution.process import Failure

logger = logging.getLogger(__name__)

# Exit code returned when a command is killed for exceeding its timeout.
TIMEOUT_EXIT_CODE = 124


class ExecAction(Action):
    name = "exec"
    help = "Run a command within the selected execution context."

    timeout: float | None = option(
        convert=float,
        help="Kill the command if it runs longer than this (default: no limit).",
    )
    argv: list[str] = remainder(
        help="The command to run, after a double-hyphen (reposcan exec -- semgrep -h)."
    )

    def run(self) -> int:
        with start_session(self.backend, tool_image=True, image=self.image) as session:
            if not session.ok:
                return session.exit_code
            return execute(session.context, self.argv, timeout=self.timeout)


def execute(
    context: ExecutionContext, command: list[str], *, timeout: float | None
) -> int:
    """Run `command` in the already-started `context` and return an exit code.

    Returns the command's own exit code when it ran, 2 for a usage error, 124 on
    timeout, or 1 when it could not be started.
    """
    if not command:
        logger.error("no command given")
        return 2
    result = context.run(command, timeout=timeout)
    if isinstance(result, Failure):
        logger.error("%s", result.reason)
        return TIMEOUT_EXIT_CODE if result.timed_out else 1
    # Forward the command's own output verbatim; this is program output, not a log.
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    return result.exit_code

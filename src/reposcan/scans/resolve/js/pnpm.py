# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The pnpm package manager: `pnpm install --lockfile-only`."""

import logging

from reposcan.execution.context import ExecutionContext
from reposcan.execution.process import succeeded
from reposcan.tools.registry import PNPM

logger = logging.getLogger(__name__)

# run pnpm without update checks
_ENV = {"PNPM_CONFIG_UPDATE_NOTIFIER": "false"}


class Pnpm:
    """Resolves a pnpm workspace (`pnpm-workspace.yaml`, no `pnpm-lock.yaml`).

    A pnpm workspace declares catalogs and shared versions in `pnpm-workspace.yaml`
    that npm cannot read; `pnpm install --lockfile-only` resolves the whole workspace
    into a `pnpm-lock.yaml` the SBOM tools read, without installing.
    """

    def can_resolve(self, names: set[str]) -> bool:
        """Whether `names` holds a `pnpm-workspace.yaml` and no `pnpm-lock.yaml`."""
        return "pnpm-workspace.yaml" in names and "pnpm-lock.yaml" not in names

    def resolve(
        self,
        ctx: ExecutionContext,
        workdir: str,
        names: set[str],
        tool_root: str,
        *,
        allow_code_execution: bool,
    ) -> None:
        """Write a `pnpm-lock.yaml` for the workspace in `workdir`, best-effort."""
        pnpm = PNPM.installed_path(tool_root)
        command = [pnpm, "install", "--lockfile-only", "--ignore-scripts"]
        logger.debug("detected pnpm; running: %s", " ".join(command))
        if succeeded(ctx.run(command, cwd=workdir, env=_ENV)):
            logger.debug("resolved pnpm workspace in %s", workdir)
        else:
            logger.warning("pnpm resolution skipped for %s: install failed", workdir)

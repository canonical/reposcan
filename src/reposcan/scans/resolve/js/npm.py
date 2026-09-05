# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The npm package manager: `npm install --package-lock-only`."""

import logging

from reposcan.execution.context import ExecutionContext
from reposcan.result import is_err

logger = logging.getLogger(__name__)

_NATIVE_LOCKS = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lockb",
        "bun.lock",
    }
)

# reduce npm noise
_ENV = {
    "NPM_CONFIG_FUND": "false",
    "NPM_CONFIG_AUDIT": "false",
    "NPM_CONFIG_UPDATE_NOTIFIER": "false",
}


class Npm:
    """Resolves a `package.json` project into a `package-lock.json`.

    Covers npm, Yarn, and Bun, which declare their dependencies in `package.json`;
    `npm install --package-lock-only` resolves that to a `package-lock.json` the SBOM
    tools read, without installing or running lifecycle scripts.
    """

    def can_resolve(self, names: set[str]) -> bool:
        """Whether `names` holds a `package.json` with no lock and no pnpm workspace."""
        return (
            "package.json" in names
            and not (names & _NATIVE_LOCKS)
            and "pnpm-workspace.yaml" not in names
        )

    def resolve(
        self,
        ctx: ExecutionContext,
        workdir: str,
        names: set[str],
        install_dir: str,
        *,
        allow_code_execution: bool,
    ) -> None:
        """Write a `package-lock.json` for the project in `workdir`."""
        # npm ships with the Node install (registry.NODE, also_link), at bin/npm.
        npm = f"{install_dir}/bin/npm"
        command = [npm, "install", "--package-lock-only", "--ignore-scripts"]
        logger.debug("detected npm; running: %s", " ".join(command))
        if is_err(ctx.run(command, cwd=workdir, env=_ENV, check=True)):
            logger.warning("npm resolution skipped for %s: install failed", workdir)
        else:
            logger.debug("resolved npm project in %s", workdir)

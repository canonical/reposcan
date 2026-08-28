# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The Pipenv package manager: `pipenv lock` + `pipenv requirements`."""

import logging

from reposcan.execution.context import ExecutionContext, write_file
from reposcan.execution.process import ExecResult, succeeded
from reposcan.tools.registry import PIPENV

logger = logging.getLogger(__name__)

# pipenv without spinners; ignore any ambient virtualenv so it resolves the Pipfile.
_ENV = {"PIPENV_NOSPIN": "1", "PIPENV_IGNORE_VIRTUALENVS": "1"}

# A distinct *requirements*.txt name the catalogers pick up without clobbering a
# repo file.
_LOCK = "reposcan-resolved.pipfile.requirements.txt"


class Pipenv:
    """Resolves a Pipenv project (`Pipfile`, no `Pipfile.lock`).

    Runs `pipenv lock` then writes `pipenv requirements` (which prints the locked
    dependencies) to a pinned requirements file the SBOM tools read. A directory that
    already ships a `Pipfile.lock` is left alone (the SBOM tools read it directly).
    """

    def can_resolve(self, names: set[str]) -> bool:
        """Whether `names` holds a `Pipfile` and no `Pipfile.lock`."""
        return "Pipfile" in names and "Pipfile.lock" not in names

    def resolve(
        self,
        ctx: ExecutionContext,
        workdir: str,
        names: set[str],
        tool_root: str,
        *,
        allow_code_execution: bool,
    ) -> None:
        """Lock and export a Pipenv project's dependencies, best-effort."""
        pipenv = PIPENV.installed_path(tool_root)
        logger.debug("detected pipenv; running: %s lock", pipenv)
        if not succeeded(ctx.run([pipenv, "lock"], cwd=workdir, env=_ENV)):
            logger.warning("pipenv resolution skipped for %s: lock failed", workdir)
            return
        # `pipenv requirements` prints the locked deps to stdout (it has no output
        # flag), so capture it and write the file ourselves.
        exported = ctx.run([pipenv, "requirements"], cwd=workdir, env=_ENV)
        if not isinstance(exported, ExecResult) or exported.exit_code != 0:
            logger.warning(
                "pipenv resolution skipped for %s: requirements failed", workdir
            )
            return
        if write_file(ctx, _LOCK, exported.stdout, cwd=workdir):
            logger.debug("resolved pipenv project in %s", workdir)
        else:
            logger.warning(
                "pipenv resolution skipped for %s: could not write lock", workdir
            )

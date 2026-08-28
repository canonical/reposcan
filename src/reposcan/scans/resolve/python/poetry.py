# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The Poetry package manager: `poetry lock` + `poetry export`."""

import logging

from reposcan.execution.context import ExecutionContext, read_file
from reposcan.execution.process import succeeded
from reposcan.tools.registry import POETRY

logger = logging.getLogger(__name__)

# poetry lock and export need no interactivity and no project virtualenv: they only
# resolve dependency metadata and read the lock.
_ENV = {"POETRY_NO_INTERACTION": "1", "POETRY_VIRTUALENVS_CREATE": "false"}

# A distinct *requirements*.txt name the catalogers pick up without clobbering a
# repo file.
_LOCK = "reposcan-resolved.poetry.requirements.txt"


class Poetry:
    """Resolves a legacy Poetry project (`[tool.poetry]`, no PEP 621 `[project]`).

    Poetry >=2.0 can declare dependencies under PEP 621 `[project]`, which the uv
    package manager already handles; this covers the legacy
    `[tool.poetry.dependencies]` table uv does not read. It runs `poetry lock` then
    exports a pinned requirements file the SBOM tools read. A directory that already
    ships a `poetry.lock` is left alone (the SBOM tools read it directly).
    """

    def can_resolve(self, names: set[str]) -> bool:
        """Whether `names` holds a `pyproject.toml` and no `poetry.lock`."""
        return "pyproject.toml" in names and "poetry.lock" not in names

    def resolve(
        self,
        ctx: ExecutionContext,
        workdir: str,
        names: set[str],
        tool_root: str,
        *,
        allow_code_execution: bool,
    ) -> None:
        """Lock and export a legacy Poetry project's dependencies, best-effort."""
        content = read_file(ctx, f"{workdir}/pyproject.toml")
        if content is None or not _is_legacy_poetry(content):
            return  # PEP 621 or not Poetry at all: the uv package manager handles it
        poetry = POETRY.installed_path(tool_root)
        logger.debug("detected poetry; running: %s lock", poetry)
        if not succeeded(ctx.run([poetry, "lock"], cwd=workdir, env=_ENV)):
            logger.warning("poetry resolution skipped for %s: lock failed", workdir)
            return
        export = [
            poetry,
            "export",
            "-f",
            "requirements.txt",
            "--without-hashes",
            "-o",
            _LOCK,
        ]
        if succeeded(ctx.run(export, cwd=workdir, env=_ENV)):
            logger.debug("resolved poetry project in %s", workdir)
        else:
            logger.warning("poetry resolution skipped for %s: export failed", workdir)


def _is_legacy_poetry(content: str) -> bool:
    """Whether a pyproject.toml is a legacy Poetry project uv cannot read.

    True when it declares `[tool.poetry]` but no PEP 621 `[project]` table (which uv
    resolves instead).
    """
    lines = [line.strip() for line in content.splitlines()]
    return "[tool.poetry]" in lines and "[project]" not in lines

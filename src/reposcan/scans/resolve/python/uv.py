# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The uv package manager: `uv pip compile` over uv-resolvable manifests."""

import logging

from reposcan.execution.context import ExecutionContext, read_file
from reposcan.execution.process import ExecResult, succeeded
from reposcan.tools.registry import UV, UV_PYTHON_SUBDIR

logger = logging.getLogger(__name__)

# Native lockfiles that already pin a directory's Python dependencies; the SBOM tools
# read them directly, so a directory holding one is left alone.
_NATIVE_LOCKS = frozenset(
    {"uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock", "pylock.toml"}
)


class Uv:
    """Resolves Python dependencies with `uv pip compile`.

    Handles the inputs uv resolves without a project-specific tool: PEP 621
    `[project]` metadata in `pyproject.toml`, `requirements*.txt`/`.in` files, and a
    static `setup.cfg`. Legacy Poetry/PDM/Pipenv manifests are left to their own
    package managers; a directory that already ships a native lockfile is skipped.
    """

    def can_resolve(self, names: set[str]) -> bool:
        """Whether `names` holds a uv-resolvable manifest and no native lock."""
        return not (names & _NATIVE_LOCKS) and _has_manifest(names)

    def resolve(
        self,
        ctx: ExecutionContext,
        workdir: str,
        names: set[str],
        tool_root: str,
        *,
        allow_code_execution: bool,
    ) -> None:
        """Compile each uv-resolvable input in `workdir` into a pinned lockfile."""
        for input_name in self._inputs(ctx, workdir, names):
            self._compile(ctx, workdir, input_name, tool_root, allow_code_execution)

    def _inputs(
        self, ctx: ExecutionContext, workdir: str, names: set[str]
    ) -> list[str]:
        """The manifest files in `workdir` uv should compile, in a stable order."""
        inputs: list[str] = []
        pep621 = False
        if "pyproject.toml" in names:
            content = read_file(ctx, f"{workdir}/pyproject.toml")
            if content is not None and _is_pep621(content):
                inputs.append("pyproject.toml")
                pep621 = True
        for name in sorted(names):
            if _is_requirements_in(name):
                inputs.append(name)  # a `.in` is meant to be compiled
            elif _is_requirements_txt(name):
                content = read_file(ctx, f"{workdir}/{name}")
                # A fully pinned requirements.txt is already a lock the SBOM tools read.
                if content is not None and _has_unpinned_requirement(content):
                    inputs.append(name)
        # setup.cfg only when a PEP 621 pyproject did not already cover the directory.
        if not pep621 and "setup.cfg" in names:
            content = read_file(ctx, f"{workdir}/setup.cfg")
            if content is not None and "install_requires" in content:
                inputs.append("setup.cfg")
        return inputs

    def _compile(
        self,
        ctx: ExecutionContext,
        workdir: str,
        input_name: str,
        tool_root: str,
        allow_code_execution: bool,
    ) -> None:
        # A distinct `*requirements*.txt` name so the catalogers pick it up, but one
        # that never clobbers a repo file or another input's lock in the same dir.
        lock = f"reposcan-resolved.{input_name.replace('.', '-')}.requirements.txt"
        base = [
            UV.installed_path(tool_root),
            "pip",
            "compile",
            input_name,
            "-o",
            lock,
            "--no-header",
        ]
        # Point uv at the managed Python baked under the install root; as the scan user
        # it has no Python of its own and would otherwise try to fetch one at scan time.
        env = {"UV_PYTHON_INSTALL_DIR": f"{tool_root}/{UV_PYTHON_SUBDIR}"}
        wheel_only = [*base, "--only-binary", ":all:"]
        logger.debug("detected python; running: %s", " ".join(wheel_only))
        result = ctx.run(wheel_only, cwd=workdir, env=env)
        if succeeded(result):
            logger.debug("resolved %s (wheel-only)", input_name)
            return
        if allow_code_execution:
            # Retry allowing source builds so source-only packages resolve (runs code).
            logger.debug("retrying %s with source builds", input_name)
            result = ctx.run(base, cwd=workdir, env=env)
            if succeeded(result):
                logger.info("resolved %s (with source builds)", input_name)
                return
        stderr = result.stderr.strip() if isinstance(result, ExecResult) else ""
        note = stderr.splitlines()[-1] if stderr else "resolver unavailable"
        logger.warning("python resolution skipped for %s: %s", input_name, note)


def _has_manifest(names: set[str]) -> bool:
    """Whether `names` holds any file uv can resolve from."""
    return (
        "pyproject.toml" in names
        or "setup.cfg" in names
        or any(_is_requirements_in(n) or _is_requirements_txt(n) for n in names)
    )


def _is_requirements_txt(name: str) -> bool:
    return name.startswith("requirements") and name.endswith(".txt")


def _is_requirements_in(name: str) -> bool:
    return name.startswith("requirements") and name.endswith(".in")


def _is_pep621(content: str) -> bool:
    """Whether a pyproject.toml declares a PEP 621 `[project]` table (uv reads it)."""
    return any(line.strip() == "[project]" for line in content.splitlines())


def _has_unpinned_requirement(content: str) -> bool:
    """Whether a requirements file has a dependency line that is not `==`-pinned.

    A dependency line is a non-blank line that is neither a comment nor an option
    (e.g. `-r other.txt`, `--hash=...`). A file whose every dependency is pinned is
    already a lock, so it is not worth recompiling.
    """
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if "==" not in line:
            return True
    return False

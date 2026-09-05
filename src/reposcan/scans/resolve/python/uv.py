# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The uv package manager: `uv pip compile` over uv-resolvable manifests."""

import logging

from reposcan.execution.context import ExecutionContext, read_file
from reposcan.result import is_err
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
        install_dir: str,
        *,
        allow_code_execution: bool,
    ) -> None:
        """Compile each uv-resolvable input in `workdir` into a pinned lockfile."""
        for input_name in self._find_inputs(ctx, workdir, names):
            self._compile(ctx, workdir, input_name, install_dir, allow_code_execution)

    def _find_inputs(
        self, ctx: ExecutionContext, workdir: str, names: set[str]
    ) -> list[str]:
        """Find uv-resolvable manifest files in `workdir`."""
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
        install_dir: str,
        allow_code_execution: bool,
    ) -> None:
        # A distinct `*requirements*.txt` name so the catalogers pick it up, but one
        # that never clobbers a repo file or another input's lock in the same dir.
        lock = f"reposcan-resolved.{input_name.replace('.', '-')}.requirements.txt"
        base = [
            UV.locate_executable(install_dir),
            "pip",
            "compile",
            input_name,
            "-o",
            lock,
            "--no-header",
        ]
        # Point uv at the managed Python baked under the install root; as the scan user
        # it has no Python of its own and would otherwise try to fetch one at scan time.
        env = {"UV_PYTHON_INSTALL_DIR": f"{install_dir}/{UV_PYTHON_SUBDIR}"}
        # `--only-binary :all:` blocks local builds and constrains resolution: a pkg
        # version published as sdist-only is passed over for an older one with a wheel.
        command = base if allow_code_execution else [*base, "--only-binary", ":all:"]
        logger.debug("detected python; running: %s", " ".join(command))
        result = ctx.run(command, cwd=workdir, env=env, check=True)
        if is_err(result):
            lines = result.msg.strip().splitlines()
            note = lines[-1] if lines else "resolver unavailable"
            logger.warning("python resolution skipped for %s: %s", input_name, note)
            return
        logger.debug("resolved %s", input_name)


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

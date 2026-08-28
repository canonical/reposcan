# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Test the dependency-resolution pre-step (reposcan.scans.resolve)."""

from collections.abc import Mapping, Sequence

from reposcan.execution.process import ExecResult, Failure
from reposcan.scans.resolve import resolve_dependencies

TARGET = "/scan/acme"
RESOLVED_PARENT = "/resolved-deps"
TOOL_ROOT = "/opt/reposcan"
DEST = f"{RESOLVED_PARENT}/acme"


def _z(*paths: str) -> str:
    return "\0".join(paths)


class _FakeContext:
    """Serves canned `git ls-files`/`cat` output and records every run.

    `tracked` is the NUL-joined `git ls-files -z`; `files` maps a path to its `cat`
    text; a `uv pip compile` whose input is in `unsatisfiable` exits non-zero.
    """

    name = "fake"

    def __init__(
        self,
        tracked: str,
        files: Mapping[str, str] | None = None,
        unsatisfiable: Sequence[str] = (),
    ) -> None:
        self._tracked = tracked
        self._files = dict(files or {})
        self._unsatisfiable = set(unsatisfiable)
        self.runs: list[tuple[list[str], str | None]] = []

    def start(self) -> None: ...
    def stop(self) -> None: ...

    def run(
        self, command: Sequence[str], *, cwd: str | None = None, **_: object
    ) -> ExecResult | Failure:
        cmd = list(command)
        self.runs.append((cmd, cwd))
        if cmd[0] == "git":
            return ExecResult(0, self._tracked, "")
        if cmd[0] == "cat":
            if cmd[1] in self._files:
                return ExecResult(0, self._files[cmd[1]], "")
            return ExecResult(1, "", "")
        if "compile" in cmd and cmd[cmd.index("compile") + 1] in self._unsatisfiable:
            return ExecResult(1, "", "no wheel available")
        return ExecResult(0, "", "")  # compile ok, mkdir, rm, cp

    def compiled(self) -> list[tuple[str, str | None]]:
        """The (input, working-directory) of each `uv pip compile` that ran."""
        index = "compile"
        return [(c[c.index(index) + 1], cwd) for c, cwd in self.runs if index in c]

    def copied(self) -> bool:
        return any(cmd[0] == "cp" for cmd, _ in self.runs)


def test_compiles_exactly_the_resolvable_python_inputs_at_any_depth() -> None:
    # Compiled (each in its own dir, dirs sorted): PEP 621 pyproject, unpinned
    # requirements.txt, static setup.cfg. Skipped: a natively-locked dir, a fully
    # `==`-pinned requirements.txt, a Poetry-only ([tool.poetry]) pyproject.
    ctx = _FakeContext(
        _z(
            "pyproject.toml",
            "svc/requirements.txt",
            "lib/setup.cfg",
            "locked/pyproject.toml",
            "locked/poetry.lock",
            "pinned/requirements.txt",
            "poetry/pyproject.toml",
        ),
        files={
            f"{DEST}/pyproject.toml": "[project]\nname = 'acme'\n",
            f"{DEST}/svc/requirements.txt": "flask\nrequests>=2\n",
            f"{DEST}/lib/setup.cfg": "[options]\ninstall_requires =\n    click\n",
            f"{DEST}/pinned/requirements.txt": "flask==3.0.0\n",
            f"{DEST}/poetry/pyproject.toml": "[tool.poetry]\nname = 'acme'\n",
        },
    )

    result = resolve_dependencies(ctx, TARGET, TOOL_ROOT, RESOLVED_PARENT)

    assert result == DEST
    assert ctx.compiled() == [
        ("pyproject.toml", DEST),
        ("setup.cfg", f"{DEST}/lib"),
        ("requirements.txt", f"{DEST}/svc"),
    ]
    # wheel-only by default (no code runs), via the installed uv.
    first = next(cmd for cmd, _ in ctx.runs if "compile" in cmd)
    assert "--only-binary" in first and first[0] == f"{TOOL_ROOT}/bin/uv"


def test_allow_code_execution_retries_with_source_builds() -> None:
    # Wheel-only unsatisfiable: the default gives up, but the flag retries without it.
    ctx = _FakeContext(
        _z("requirements.txt"),
        files={f"{DEST}/requirements.txt": "source-only-pkg\n"},
        unsatisfiable=["requirements.txt"],
    )

    resolve_dependencies(
        ctx, TARGET, TOOL_ROOT, RESOLVED_PARENT, allow_code_execution=True
    )

    attempts = [cmd for cmd, _ in ctx.runs if "compile" in cmd]
    assert len(attempts) == 2
    assert "--only-binary" in attempts[0] and "--only-binary" not in attempts[1]


def test_leaves_target_unchanged_without_resolvable_python() -> None:
    # No Python manifest, and a non-git target whose `git ls-files` fails: both no-op
    # (best-effort), returning the original target and copying nothing.
    class _NoGit(_FakeContext):
        def run(self, command, **kwargs):  # type: ignore[no-untyped-def]
            if list(command)[0] == "git":
                return Failure(reason="not a git repository")
            return super().run(command, **kwargs)

    for ctx in (_FakeContext(_z("README.md", "src/app.go")), _NoGit(_z())):
        assert resolve_dependencies(ctx, TARGET, TOOL_ROOT, RESOLVED_PARENT) == TARGET
        assert not ctx.copied()


def test_resolves_a_legacy_poetry_project() -> None:
    # [tool.poetry] with no [project] (and no poetry.lock): uv skips it; poetry locks
    # and exports a pinned requirements file the catalogers read.
    ctx = _FakeContext(
        _z("pyproject.toml"),
        files={f"{DEST}/pyproject.toml": "[tool.poetry]\nname = 'acme'\n"},
    )

    assert resolve_dependencies(ctx, TARGET, TOOL_ROOT, RESOLVED_PARENT) == DEST
    ran = [cmd for cmd, _ in ctx.runs]
    poetry = f"{TOOL_ROOT}/bin/poetry"
    assert [poetry, "lock"] in ran and any(cmd[:2] == [poetry, "export"] for cmd in ran)
    assert ctx.compiled() == []  # uv did not resolve a legacy-Poetry pyproject


def test_poetry_defers_to_uv_when_pep621_metadata_is_present() -> None:
    # A Poetry >=2.0 pyproject that also declares [project] is uv's job; poetry stays
    # out.
    ctx = _FakeContext(
        _z("pyproject.toml"),
        files={f"{DEST}/pyproject.toml": "[project]\nname = 'acme'\n[tool.poetry]\n"},
    )

    resolve_dependencies(ctx, TARGET, TOOL_ROOT, RESOLVED_PARENT)
    assert ctx.compiled() == [("pyproject.toml", DEST)]
    assert not any("poetry" in cmd[0] for cmd, _ in ctx.runs)


def test_resolves_a_pipenv_project_writing_the_captured_requirements() -> None:
    # Pipfile with no Pipfile.lock: pipenv locks, then its stdout `requirements` are
    # written to a *requirements*.txt (pipenv has no output flag).
    ctx = _FakeContext(_z("Pipfile"), files={f"{DEST}/Pipfile": "[packages]\n"})

    assert resolve_dependencies(ctx, TARGET, TOOL_ROOT, RESOLVED_PARENT) == DEST
    ran = [cmd for cmd, _ in ctx.runs]
    pipenv = f"{TOOL_ROOT}/bin/pipenv"
    assert [pipenv, "lock"] in ran and [pipenv, "requirements"] in ran
    # the captured stdout is written to a *requirements*.txt via `cp /dev/stdin`.
    assert any(
        cmd[:2] == ["cp", "/dev/stdin"] and cmd[-1].endswith("requirements.txt")
        for cmd in ran
    )


def test_skips_poetry_and_pipenv_directories_that_are_already_locked() -> None:
    # poetry.lock / Pipfile.lock mean the deps are pinned and the SBOM tools read them.
    ctx = _FakeContext(
        _z("pyproject.toml", "poetry.lock", "svc/Pipfile", "svc/Pipfile.lock"),
        files={f"{DEST}/pyproject.toml": "[tool.poetry]\n"},
    )

    assert resolve_dependencies(ctx, TARGET, TOOL_ROOT, RESOLVED_PARENT) == TARGET
    assert not ctx.copied()


def test_resolves_js_projects_dispatching_npm_and_pnpm() -> None:
    # Root package.json -> npm; a pnpm workspace -> pnpm
    ctx = _FakeContext(
        _z("package.json", "svc/package.json", "svc/pnpm-workspace.yaml")
    )

    assert resolve_dependencies(ctx, TARGET, TOOL_ROOT, RESOLVED_PARENT) == DEST
    npm = [f"{TOOL_ROOT}/bin/npm", "install", "--package-lock-only", "--ignore-scripts"]
    pnpm = [f"{TOOL_ROOT}/bin/pnpm", "install", "--lockfile-only", "--ignore-scripts"]
    assert (npm, DEST) in ctx.runs
    assert (pnpm, f"{DEST}/svc") in ctx.runs
    assert (npm, f"{DEST}/svc") not in ctx.runs  # npm defers in the pnpm workspace


def test_skips_js_directories_that_are_already_locked() -> None:
    # A committed package-lock.json / pnpm-lock.yaml is read by the SBOM tools directly.
    ctx = _FakeContext(
        _z(
            "package.json",
            "package-lock.json",
            "ws/pnpm-workspace.yaml",
            "ws/pnpm-lock.yaml",
        )
    )

    assert resolve_dependencies(ctx, TARGET, TOOL_ROOT, RESOLVED_PARENT) == TARGET
    assert not ctx.copied()

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the `reposcan image build` action (reposcan.actions.image)."""

import io
from collections.abc import Iterator
from contextlib import contextmanager, redirect_stdout

import reposcan.actions.image as image_cmd
import reposcan.backends as backends
from reposcan.execution.process import ExecResult, Failure
from reposcan.image.spec import BuildSpec


@contextmanager
def _mocks(result: str | Failure) -> Iterator[dict[str, bool]]:
    """Make every backend available and script what a build returns."""
    seen: dict[str, bool] = {}

    def fake_build(builder: object, spec: BuildSpec, *, force: bool) -> str | Failure:
        seen["force"] = force
        return result

    saved_built, saved_run = backends.ensure_built, backends.run_process
    backends.ensure_built = fake_build
    backends.run_process = lambda *a, **k: ExecResult(0, "", "")
    try:
        yield seen
    finally:
        backends.ensure_built, backends.run_process = saved_built, saved_run


def test_success_prints_the_reference_and_forwards_force() -> None:
    out = io.StringIO()
    with _mocks("reposcan:deadbeef12") as seen, redirect_stdout(out):
        code = image_cmd.ImageBuild(backend="docker", force=True).run()
    assert code == 0
    assert "reposcan:deadbeef12" in out.getvalue()
    assert seen["force"] is True  # --force reached ensure_built


def test_build_failure_returns_one() -> None:
    with _mocks(Failure(reason="docker build failed")):
        code = image_cmd.ImageBuild(backend="docker", force=False).run()
    assert code == 1


def test_local_backend_is_a_usage_error() -> None:
    assert image_cmd.ImageBuild(backend="local", force=False).run() == 2

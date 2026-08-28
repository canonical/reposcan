# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the `reposcan image build` action (reposcan.actions.image).

The builder is chosen by the action and passed in, so this covers only
build/print/force and the failure exit code. `ensure_image` is patched so no daemon
is touched.
"""

import io
from collections.abc import Iterator
from contextlib import contextmanager, redirect_stdout

import reposcan.actions.image as image_cmd
from reposcan.execution.process import Failure
from reposcan.image.build_spec import BuildSpec
from reposcan.image.docker import DockerImageBuilder


@contextmanager
def _patched_ensure(result: str | Failure) -> Iterator[dict[str, bool]]:
    seen: dict[str, bool] = {}

    def fake(builder: object, spec: BuildSpec, *, force: bool) -> str | Failure:
        seen["force"] = force
        return result

    saved = image_cmd.ensure_image
    image_cmd.ensure_image = fake
    try:
        yield seen
    finally:
        image_cmd.ensure_image = saved


def test_success_prints_the_reference_and_forwards_force() -> None:
    out = io.StringIO()
    with _patched_ensure("reposcan:deadbeef12") as seen, redirect_stdout(out):
        code = image_cmd.build_image(DockerImageBuilder(), force=True)
    assert code == 0
    assert "reposcan:deadbeef12" in out.getvalue()
    assert seen["force"] is True  # --force reached ensure_image


def test_build_failure_returns_one() -> None:
    with _patched_ensure(Failure(reason="docker build failed")):
        code = image_cmd.build_image(DockerImageBuilder(), force=False)
    assert code == 1

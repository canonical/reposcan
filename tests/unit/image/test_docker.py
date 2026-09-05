# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the Docker image builder (reposcan.image.docker).

docker is not invoked: run_process is patched with a fake that records the argv.
"""

from collections.abc import Mapping, Sequence
from contextlib import contextmanager

import reposcan.image.docker as docker
from reposcan.execution.process import ExecResult
from reposcan.image.spec import BuildSpec
from reposcan.result import Err, Result

_SPEC = BuildSpec("ubuntu:24.04", "/opt/reposcan", "#!/bin/sh\ntrue\n")
_BUILDER = docker.DockerImageBuilder()


@contextmanager
def _patched(result: Result[ExecResult]):
    calls: list[list[str]] = []

    def fake(
        command: Sequence[str],
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float | None = None,
        check: bool = False,
        stream_stdout: bool = False,
        stream_stderr: bool = False,
    ) -> Result[ExecResult]:
        calls.append(list(command))
        return result

    saved = docker.run_process
    docker.run_process = fake
    try:
        yield calls
    finally:
        docker.run_process = saved


def test_build_runs_docker_build_for_the_tag_and_propagates_failure() -> None:
    with _patched(ExecResult(0, "", "")) as calls:
        built = _BUILDER.build(_SPEC)
    assert not isinstance(built, Err)
    assert built == f"reposcan:{_SPEC.short_digest}"
    assert calls[-1][:4] == ["docker", "build", "-t", built]
    with _patched(Err("docker build failed")):
        failed = _BUILDER.build(_SPEC)
    assert failed == Err("docker build failed")  # build error surfaced


def test_identity_is_the_image_id_or_none_when_absent() -> None:
    with _patched(ExecResult(0, "sha256:abc\n", "")) as calls:
        assert _BUILDER.read_identity("reposcan:x") == "sha256:abc"
    assert calls[0][:3] == ["docker", "image", "inspect"]
    with _patched(Err("No such image")):
        assert _BUILDER.read_identity("reposcan:x") is None

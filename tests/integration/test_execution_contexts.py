# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests for the container execution contexts.

Unlike the unit tests, these invoke real docker / lxc and start real ephemeral
ubuntu:26.04 containers. They are excluded from the default unit run
(`testpaths = ["tests/unit"]`); run them explicitly with:

    tox run -f integration      (across the py310/py312/py314 matrix)
    OR
    tox run -e integration-py310
    OR
    pytest tests/integration -s --log-cli-level=INFO

Each test skips cleanly when its backend is unavailable, so this is safe to run
on a host with only one (or neither) backend. The LXD image may be downloaded on
first run, so the first lxd test can be slow; progress is logged at INFO (the tox
integration envs pass -s --log-cli-level=INFO so it shows live, or pass them to
pytest yourself).
"""

import logging
import tempfile
from pathlib import Path

import pytest

from reposcan.backends import DockerBackend, LxdBackend
from reposcan.execution.context import ExecutionContext, mounted_target
from reposcan.execution.process import ExecResult, Failure

logger = logging.getLogger(__name__)


def _exercise_lifecycle(ctx: ExecutionContext) -> None:
    """Run a series of commands in an already-started context and check that they
    execute inside the ubuntu:26.04 container with cwd/env/exit-code honored."""
    # Runs in the ubuntu:26.04 image, not on the host.
    os_release = ctx.run(["cat", "/etc/os-release"])
    assert isinstance(os_release, ExecResult), os_release
    assert os_release.ok
    assert 'VERSION_ID="26.04"' in os_release.stdout

    # The command's exit code is propagated.
    exit_code = ctx.run(["sh", "-c", "exit 7"])
    assert isinstance(exit_code, ExecResult), exit_code
    assert exit_code.exit_code == 7

    # Per-command env reaches the container.
    env = ctx.run(["sh", "-c", "echo $REPOSCAN_IT"], env={"REPOSCAN_IT": "present"})
    assert isinstance(env, ExecResult), env
    assert env.stdout.strip() == "present"

    # cwd is honored.
    cwd = ctx.run(["pwd"], cwd="/tmp")
    assert isinstance(cwd, ExecResult), cwd
    assert cwd.stdout.strip() == "/tmp"


def test_docker_context_lifecycle() -> None:
    backend = DockerBackend()
    availability = backend.availability()
    if not availability.ok:
        logger.warning(availability.reason)
        pytest.skip(f"docker unavailable: {availability.reason}")

    logger.info("[docker] starting ubuntu:26.04 container")
    ctx = backend.context()
    started = ctx.start()
    assert started is None, f"docker run failed: {started}"
    try:
        _exercise_lifecycle(ctx)
    finally:
        ctx.stop()

    # After stop the context has no running container.
    assert isinstance(ctx.run(["true"]), Failure)


def test_docker_context_mounts_a_source_read_only() -> None:
    backend = DockerBackend()
    availability = backend.availability()
    if not availability.ok:
        logger.warning(availability.reason)
        pytest.skip(f"docker unavailable: {availability.reason}")

    with tempfile.TemporaryDirectory() as source:
        Path(source, "marker.txt").write_text("hello")
        target = mounted_target(source)
        logger.info("[docker] mounting %s at %s", source, target)
        ctx = backend.context(mount_source=source)
        assert ctx.start() is None
        try:
            # The mounted file is visible inside the container at the kept-name path.
            seen = ctx.run(["cat", f"{target}/marker.txt"])
            assert isinstance(seen, ExecResult) and seen.ok, seen
            assert seen.stdout.strip() == "hello"
            # The mount is read-only: writing into it fails.
            write = ctx.run(["sh", "-c", f"echo x > {target}/new.txt"])
            assert isinstance(write, ExecResult) and not write.ok, write
        finally:
            ctx.stop()


def test_lxd_context_lifecycle() -> None:
    backend = LxdBackend()
    availability = backend.availability()
    if not availability.ok:
        logger.warning(availability.reason)
        pytest.skip(f"lxd unavailable: {availability.reason}")

    logger.info("[lxd] launching ubuntu:26.04 container (may download the image)")
    ctx = backend.context()
    started = ctx.start()
    # If this fails right after launch, the container may not be ready to exec yet
    # and LxdContext.start would need a readiness wait.
    assert started is None, f"lxc launch failed: {started}"
    try:
        _exercise_lifecycle(ctx)
    finally:
        ctx.stop()

    # After stop the context has no running container.
    assert isinstance(ctx.run(["true"]), Failure)

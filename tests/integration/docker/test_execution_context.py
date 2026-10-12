# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests using the docker execution context."""

import logging
import tempfile
from pathlib import Path

from reposcan.backends import BACKENDS
from reposcan.execution.context import locate_mounted_target
from reposcan.execution.docker import DockerContext
from reposcan.image.spec import BASE_IMAGE
from reposcan.result import Err
from tests.integration.shared import exercise_lifecycle

logger = logging.getLogger(__name__)


def test_docker_context_lifecycle() -> None:
    backend = BACKENDS["docker"]
    available = backend.check_availability()
    assert not isinstance(available, Err), f"docker unavailable: {available.msg}"

    logger.info("[docker] starting ubuntu:26.04 container")
    ctx = DockerContext(BASE_IMAGE)
    started = ctx.start()
    assert started is None, f"docker run failed: {started}"
    try:
        exercise_lifecycle(ctx)
    finally:
        ctx.stop()

    # After stop the context has no running container.
    assert isinstance(ctx.run(["true"]), Err)


def test_docker_context_mounts_a_source_read_only() -> None:
    backend = BACKENDS["docker"]
    available = backend.check_availability()
    assert not isinstance(available, Err), f"docker unavailable: {available.msg}"

    with tempfile.TemporaryDirectory() as source:
        Path(source, "marker.txt").write_text("hello")
        target = locate_mounted_target(source)
        logger.info("[docker] mounting %s at %s", source, target)
        ctx = DockerContext(BASE_IMAGE, mount_source=source)
        assert not isinstance(ctx.start(), Err)
        try:
            # The mounted file is visible inside the container at the kept-name path.
            seen = ctx.run(["cat", f"{target}/marker.txt"])
            assert not isinstance(seen, Err) and seen.exit_code == 0, seen
            assert seen.stdout.strip() == "hello"
            # The mount is read-only: writing into it fails.
            write = ctx.run(["sh", "-c", f"echo x > {target}/new.txt"])
            assert not isinstance(write, Err) and write.exit_code != 0, write
        finally:
            ctx.stop()

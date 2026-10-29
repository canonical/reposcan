# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration test: the published image is pullable and usable.

Docker-only: LXD cannot pull, and the local backend has no image.
"""

import logging

from reposcan.backends import BACKENDS
from reposcan.execution.docker import DockerContext
from reposcan.image.ensure import ensure_pulled
from reposcan.image.spec import CANONICAL_REF
from reposcan.result import is_err
from reposcan.tools.registry import TOOLS

logger = logging.getLogger(__name__)


_TEST_CMD = "trivy"


def test_ghcr_image_is_pullable_and_runs_its_tools() -> None:
    backend = BACKENDS["docker"]
    available = backend.check_availability()
    assert not is_err(available), f"docker unavailable: {available.msg}"

    logger.info("pulling the ghcr image %s", CANONICAL_REF)
    reference = ensure_pulled(CANONICAL_REF)
    assert not is_err(reference), (
        f"could not pull the ghcr image {CANONICAL_REF}: {reference.msg}"
    )

    assert isinstance(reference, str)
    ctx = DockerContext(reference)
    started = ctx.start()
    assert started is None, f"container from the ghcr image failed to start: {started}"
    try:
        tool = TOOLS[_TEST_CMD]
        executable = tool.locate_executable("/opt/reposcan")
        logger.info("[%s] checking %s --version", _TEST_CMD, executable)
        result = ctx.run([executable, "--version"])
        assert not is_err(result)
        assert result.exit_code == 0, (
            f"{_TEST_CMD} exited {result.exit_code}: {result.stderr}"
        )
        assert tool.version in result.stdout, (
            f"the ghcr image's {_TEST_CMD} did not report the pinned version "
            f"{tool.version}: {result.stdout!r}"
        )
    finally:
        ctx.stop()

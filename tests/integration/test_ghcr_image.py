# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration test: the published image is pullable and usable.

Docker-only: LXD cannot pull, and the local backend has no image.
"""

import logging

import pytest

from reposcan.backends import DockerBackend
from reposcan.execution.process import ExecResult, Failure
from reposcan.image.remote import CANONICAL_REF, ensure_pulled
from reposcan.tools.registry import TOOLS

logger = logging.getLogger(__name__)

_TEST_CMD = "trivy"


def test_ghcr_image_is_pullable_and_runs_its_tools() -> None:
    backend = DockerBackend()
    availability = backend.availability()
    assert availability.ok, f"docker unavailable: {availability.reason}"

    puller = backend.image_puller()
    assert puller is not None  # DockerBackend can always pull

    logger.info("pulling the ghcr image %s", CANONICAL_REF)
    reference = ensure_pulled(puller, CANONICAL_REF)
    if isinstance(reference, Failure):
        pytest.fail(
            f"could not pull the ghcr image {CANONICAL_REF}: {reference.reason}"
        )

    assert isinstance(reference, str)
    ctx = backend.context(reference)
    started = ctx.start()
    assert started is None, f"container from the ghcr image failed to start: {started}"
    try:
        tool = TOOLS[_TEST_CMD]
        executable = tool.installed_path("/opt/reposcan")
        logger.info("[%s] checking %s --version", _TEST_CMD, executable)
        result = ctx.run([executable, "--version"])
        assert isinstance(result, ExecResult), result
        assert result.ok, f"{_TEST_CMD} exited {result.exit_code}: {result.stderr}"
        assert tool.version in result.stdout, (
            f"the ghcr image's {_TEST_CMD} did not report the pinned version "
            f"{tool.version}: {result.stdout!r}"
        )
    finally:
        ctx.stop()

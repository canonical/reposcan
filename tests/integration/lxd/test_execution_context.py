# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests with the lxd execution context.

The LXD image may be downloaded on first run, so the first test can be slow.
"""

import logging

from reposcan.backends import BACKENDS
from reposcan.execution.lxd import LxdContext
from reposcan.image.spec import BASE_IMAGE
from reposcan.result import is_err
from tests.integration.shared import exercise_lifecycle

logger = logging.getLogger(__name__)


def test_lxd_context_lifecycle() -> None:
    backend = BACKENDS["lxd"]
    available = backend.check_availability()
    assert not is_err(available), f"lxd unavailable: {available.msg}"

    logger.info("[lxd] launching ubuntu:26.04 container (may download the image)")
    ctx = LxdContext(BASE_IMAGE)
    started = ctx.start()
    # If this fails right after launch, the container may not be ready to exec yet
    # and LxdContext.start would need a readiness wait.
    assert started is None, f"lxc launch failed: {started}"
    try:
        exercise_lifecycle(ctx)
    finally:
        ctx.stop()

    # After stop the context has no running container.
    assert is_err(ctx.run(["true"]))

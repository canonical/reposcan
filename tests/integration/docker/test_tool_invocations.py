# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration test: build the reposcan docker image in docker and test every tool."""

import pytest

from reposcan.backends import BACKENDS
from tests.integration.shared import probe_every_tool_in


def test_every_tool_runs_in_the_docker_image(request: pytest.FixtureRequest) -> None:
    short = bool(request.config.getoption("--short"))
    probe_every_tool_in(BACKENDS["docker"], force_rebuild=not short)

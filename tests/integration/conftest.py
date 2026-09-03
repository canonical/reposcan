# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Pytest options shared by the integration tests.

Adds `--short`: reuse an already-built reposcan image when it still verifies, instead
of forcing a fresh rebuild. The LXD image build is slow, so this makes local
re-runs quick once the image exists. The tests read it with
`request.config.getoption("--short")`.

    tox run -f integration -- --short
    tox run -e integration-py310 -- --short
"""

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register the --short integration-test option."""
    parser.addoption(
        "--short",
        action="store_true",
        default=False,
        help="Reuse an existing reposcan image if it still verifies, instead of "
        "forcing a rebuild (skips the slow LXD image build).",
    )

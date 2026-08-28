# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for reposcan's own version reporting."""

from reposcan import reposcan_version


def test_the_version_comes_from_the_installed_distribution() -> None:
    # Every emitted report and every recorded analysis carries this, and the lookup
    # falls back to "unknown" rather than failing, so a distribution name that stops
    # matching the import package would go unnoticed until the reports were read.
    assert reposcan_version() != "unknown", (
        "reposcan's distribution metadata was not found. The name in pyproject.toml "
        "and the import package must match; if this fails after a rename, recreate "
        "the tox environment so the installed distribution is rebuilt."
    )

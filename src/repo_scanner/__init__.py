# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""repo-scanner: orchestrate security scans."""

from importlib.metadata import PackageNotFoundError, version


def reposcan_version() -> str:
    """The running reposcan's version, or "unknown" if its metadata is unavailable."""
    try:
        return version("repo-scanner")
    except PackageNotFoundError:
        return "unknown"

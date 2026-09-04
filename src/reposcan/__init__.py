# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""reposcan: orchestrate security scans."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version(__name__)
except PackageNotFoundError:  # not installed, e.g. imported straight from a checkout
    __version__ = "unknown"

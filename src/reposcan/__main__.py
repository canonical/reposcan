# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Enables `python -m reposcan`."""

import sys

from reposcan.app import main

if __name__ == "__main__":
    sys.exit(main())

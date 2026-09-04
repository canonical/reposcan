# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Filesystem locations reposcan uses on the local host.

Config lives under $XDG_CONFIG_HOME (see config.py); installed tools live under
$XDG_DATA_HOME; transient scratch (dependency-resolution repo copies) lives under
$XDG_CACHE_HOME, all following the XDG convention.

Resolved once at import.
"""

import os
from pathlib import Path

_DATA_HOME = Path(
    os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
)
_CACHE_HOME = Path(os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"))

# used as a working directory for dependency resolution by the local backend.
# Container backends use an in-image dirinstead (execution.context.RESOLUTION_WORKDIR).
LOCAL_RESOLUTION_WORKDIR = _CACHE_HOME / "reposcan" / "resolved"

# used when installing and running reposcan-managed executables
TOOL_INSTALL_DIR = _DATA_HOME / "reposcan" / "tools"

IMAGE_CACHE = _DATA_HOME / "reposcan" / "images.json"

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Filesystem locations reposcan uses on the local host.

Config lives under $XDG_CONFIG_HOME (see config.py); installed tools live under
$XDG_DATA_HOME; transient scratch (dependency-resolution repo copies) lives under
$XDG_CACHE_HOME, all following the XDG convention.
"""

import os
from pathlib import Path


def _data_home() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return Path(base) / "reposcan"


def _cache_home() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return Path(base) / "reposcan"


def resolve_cache() -> Path:
    """Where the local backend copies a repo to resolve its dependencies.

    $XDG_CACHE_HOME/reposcan/resolved (default ~/.cache/reposcan/resolved). Container
    backends use an in-image directory instead (see RESOLVED_PARENT).
    """
    return _cache_home() / "resolved"


def tools_root() -> Path:
    """Where `bootstrap` installs tools and `tools` looks for them.

    $XDG_DATA_HOME/reposcan/tools (default ~/.local/share/reposcan/tools).
    """
    return _data_home() / "tools"


def image_cache() -> Path:
    """Where built images' verified identities are recorded (see image/cache.py).

    $XDG_DATA_HOME/reposcan/images.json.
    """
    return _data_home() / "images.json"

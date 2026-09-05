# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Persisted config store."""

import json
import logging
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from reposcan.result import Err, Result

logger = logging.getLogger(__name__)


_CONFIG_HOME = Path(
    os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
)

# Resolved once, at import
CONFIG_FILE = _CONFIG_HOME / "reposcan" / "config.json"


def load() -> dict[str, Any]:
    """Load reposcan's saved config or return a null one {}."""
    path = CONFIG_FILE
    try:
        text = path.read_text()
    except FileNotFoundError:
        return {}
    except OSError as exc:
        logger.warning("could not read config %s: %s", path, exc)
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        logger.warning("ignoring malformed config %s: %s", path, exc)
        return {}
    return data if isinstance(data, dict) else {}


def save(settings: Mapping[str, Any]) -> Result[None]:
    """Write `settings` as JSON."""
    path = CONFIG_FILE
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(dict(settings), indent=2, sort_keys=True) + "\n")
    except OSError as exc:
        return Err(f"could not write config {path}: {exc}")
    return None

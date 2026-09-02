# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Persisted config store."""

import json
import logging
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def config_path() -> Path:
    """Locate reposcan's config file ($XDG_CONFIG_HOME/reposcan/config.json)."""
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(base) / "reposcan" / "config.json"


def load() -> dict[str, Any]:
    """Load reposcan's saved config or return a null one {}."""
    path = config_path()
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


def save(settings: Mapping[str, Any]) -> str | None:
    """Write `settings` as JSON; return an error message, or None on success."""
    path = config_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(dict(settings), indent=2, sort_keys=True) + "\n")
    except OSError as exc:
        return f"could not write config {path}: {exc}"
    return None

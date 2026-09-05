# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""A persistent record of built images' real content identity, for verifying reuse.

An image is content-addressed by its BuildSpec (the reference/tag). But the reference
only says what should be in the image; this records the real identity captured at
build time -- the Docker image ID or the LXD fingerprint -- so a later run can confirm
the image currently present is the one we built before trusting and running it.

Stored as a JSON map of reference -> identity at $XDG_DATA_HOME/reposcan/images.json.
"""

import json
import logging

from reposcan import paths
from reposcan.result import Err, Result, is_err

logger = logging.getLogger(__name__)


def load() -> dict[str, str]:
    """Load the cache: every recorded reference -> identity pair.

    Returns:
        The recorded reference -> identity map, empty if the file is missing or
        malformed (a bad cache is ignored, not fatal).
    """
    path = paths.IMAGE_CACHE
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError:
        return {}
    except OSError as exc:
        logger.warning("could not read image cache %s: %s", path, exc)
        return {}
    except json.JSONDecodeError as exc:
        logger.warning("ignoring malformed image cache %s: %s", path, exc)
        return {}
    return data if isinstance(data, dict) else {}


def _save(data: dict[str, str]) -> Result[None]:
    """Write the cache map, creating its parent directory."""
    path = paths.IMAGE_CACHE
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    except OSError as exc:
        return Err(f"could not write image cache {path}: {exc}")
    return None


def find_recorded_identity(reference: str) -> str | None:
    """Find the identity recorded for `reference`.

    This is the identity captured when reposcan built or first pulled it, not the
    one the backend reports now (see the builders' `read_identity`).
    """
    return load().get(reference)


def record(reference: str, identity: str) -> None:
    """Record the content identity of `reference`.

    A cache that cannot be written is a warning, not a failure: the image just gets
    rebuilt next time rather than reused.
    """
    data = load()
    data[reference] = identity
    if is_err(err := _save(data)):
        logger.warning("%s", err.msg)


def remove(reference: str) -> Result[bool]:
    """Drop `reference` from the cache.

    Returns:
        True if it was present and removed, False if it was not there; an error if
        the cache could not be written.
    """
    data = load()
    if reference not in data:
        return False
    del data[reference]
    return e if is_err(e := _save(data)) else True


def clear() -> Result[None]:
    """Remove every entry."""
    if not load():
        return None
    return _save({})

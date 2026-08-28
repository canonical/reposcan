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

from reposcan.execution.process import Failure
from reposcan.paths import image_cache

logger = logging.getLogger(__name__)


def entries() -> dict[str, str]:
    """Every recorded reference -> identity pair, read from the cache file.

    Returns:
        The recorded reference -> identity map, empty if the file is missing or
        malformed (a bad cache is ignored, not fatal).
    """
    path = image_cache()
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


def _save(data: dict[str, str]) -> Failure | None:
    """Write the cache map, creating its parent directory.

    Returns:
        None on success, or a Failure if it could not be written.
    """
    path = image_cache()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    except OSError as exc:
        return Failure(reason=f"could not write image cache {path}: {exc}")
    return None


def recorded(reference: str) -> str | None:
    """The identity recorded when `reference` was last built, or None if never."""
    return entries().get(reference)


def record(reference: str, identity: str) -> None:
    """Remember that `reference` was built with content identity `identity`.

    A cache that cannot be written is a warning, not a failure: the image just gets
    rebuilt next time rather than reused.
    """
    data = entries()
    data[reference] = identity
    error = _save(data)
    if error is not None:
        logger.warning("%s", error.reason)


def remove(reference: str) -> bool | Failure:
    """Drop `reference` from the cache.

    Returns:
        True if it was present and removed, False if it was not there, or a Failure
        if the cache could not be written.
    """
    data = entries()
    if reference not in data:
        return False
    del data[reference]
    error = _save(data)
    return error if error is not None else True


def clear() -> Failure | None:
    """Remove every entry.

    Returns:
        None on success (including when already empty), or a Failure if the cache
        could not be written.
    """
    if not entries():
        return None
    return _save({})

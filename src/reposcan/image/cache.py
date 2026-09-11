# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""A persistent record of built images' real content identity, for verifying reuse.

An image is content-addressed by its BuildSpec (the reference/tag). But the reference
only says what should be in the image; this records the real identity captured at
build time -- the Docker image ID or the LXD fingerprint -- so a later run can confirm
the image currently present is the one we built before trusting and running it.

Stored as a JSON map of reference -> identity at $XDG_DATA_HOME/reposcan/images.json.
Reads take a shared flock and writes take an exclusive one held across the whole
read-modify-write, so two reposcan processes touching the cache at once (a manual
`image build` alongside a `scan-repos --image build`, say) cannot lose one process's
write to the other's.
"""

import fcntl
import json
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TextIO

from reposcan import paths
from reposcan.result import Err, Result, get_value, is_err

logger = logging.getLogger(__name__)


def _parse(text: str) -> Result[dict[str, str]]:
    """Parse the cache's JSON text into a reference -> identity map.

    Returns:
        The parsed dict, an empty dict if text is not a dict, or an Err if invalid.
    """
    if not text:
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return Err(str(exc))
    return data if isinstance(data, dict) else {}


def _write(f: TextIO, data: dict[str, str]) -> Result[None]:
    """Overwrite the cache file's contents.

    Assumes `f` is positioned at 0.
    """
    try:
        f.truncate()
        f.write(json.dumps(data, indent=2, sort_keys=True) + "\n")
    except OSError as exc:
        return Err(str(exc))
    return None


@contextmanager
def _exclusive(path: Path) -> Iterator[tuple[TextIO, dict[str, str]]]:
    """Open `path` with an exclusive lock.

    Creates the parent directory if missing.

    Returns:
        The opened file handle (positioned at 0) and its parsed contents.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a+", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.seek(0)
        parsed = _parse(f.read())
        if is_err(parsed):
            logger.warning("ignoring malformed image cache %s: %s", path, parsed.msg)
        f.seek(0)
        yield f, get_value(parsed) or {}


def load() -> dict[str, str]:
    """Load the cache: every recorded reference -> identity pair.

    Returns:
        The recorded reference -> identity map, empty if the file is missing or
        malformed (a bad cache is ignored, not fatal).
    """
    path = paths.IMAGE_CACHE
    try:
        with open(path, encoding="utf-8") as f:
            fcntl.flock(f, fcntl.LOCK_SH)
            text = f.read()
    except FileNotFoundError:
        return {}
    except OSError as exc:
        logger.warning("could not read image cache %s: %s", path, exc)
        return {}
    parsed = _parse(text)
    if is_err(parsed):
        logger.warning("ignoring malformed image cache %s: %s", path, parsed.msg)
        return {}
    return get_value(parsed) or {}


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
    path = paths.IMAGE_CACHE
    with _exclusive(path) as (f, data):
        data[reference] = identity
        if is_err(err := _write(f, data)):
            logger.warning("could not write image cache %s: %s", path, err.msg)


def remove(reference: str) -> Result[bool]:
    """Drop `reference` from the cache.

    Returns:
        True if it was present and removed, False if it was not there; an error if
        the cache could not be written.
    """
    path = paths.IMAGE_CACHE
    with _exclusive(path) as (f, data):
        if reference not in data:
            return False
        del data[reference]
        if is_err(err := _write(f, data)):
            return Err(f"could not write image cache {path}: {err.msg}")
        return True


def clear() -> Result[None]:
    """Remove every entry."""
    path = paths.IMAGE_CACHE
    with _exclusive(path) as (f, data):
        if not data:
            return None
        if is_err(err := _write(f, {})):
            return Err(f"could not write image cache {path}: {err.msg}")
        return None

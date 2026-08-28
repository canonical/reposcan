# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the image identity cache (reposcan.image.cache)."""

import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager

from reposcan.image import cache
from reposcan.paths import image_cache


@contextmanager
def _isolated() -> Iterator[None]:
    saved = os.environ.get("XDG_DATA_HOME")
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["XDG_DATA_HOME"] = tmp
        try:
            yield
        finally:
            if saved is None:
                os.environ.pop("XDG_DATA_HOME", None)
            else:
                os.environ["XDG_DATA_HOME"] = saved


def test_records_and_reads_back_identities() -> None:
    with _isolated():
        assert cache.recorded("reposcan:x") is None  # nothing recorded yet
        cache.record("reposcan:x", "sha256:abc")
        cache.record("reposcan:y", "sha256:def")  # a second entry coexists
        assert cache.recorded("reposcan:x") == "sha256:abc"
        assert cache.recorded("reposcan:y") == "sha256:def"


def test_a_malformed_cache_reads_as_empty() -> None:
    with _isolated():
        path = image_cache()
        path.parent.mkdir(parents=True)
        path.write_text("{ not json")
        assert cache.recorded("reposcan:x") is None  # ignored, not fatal


def test_entries_lists_all_records_and_remove_drops_one() -> None:
    with _isolated():
        assert cache.entries() == {}
        cache.record("reposcan:x", "sha256:abc")
        cache.record("ghcr.io/acme/thing:latest", "sha256:def")
        assert cache.entries() == {
            "reposcan:x": "sha256:abc",
            "ghcr.io/acme/thing:latest": "sha256:def",
        }
        assert cache.remove("reposcan:x") is True  # present, removed
        assert cache.recorded("reposcan:x") is None
        assert cache.remove("reposcan:x") is False  # already gone


def test_clear_empties_the_cache() -> None:
    with _isolated():
        cache.record("reposcan:x", "sha256:abc")
        assert cache.clear() is None
        assert cache.entries() == {}
        assert cache.clear() is None  # already empty: still fine

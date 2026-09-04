# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the image identity cache (reposcan.image.cache)."""

import pathlib
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager

from reposcan import paths
from reposcan.image import cache


@contextmanager
def _isolated() -> Iterator[None]:
    saved = paths.IMAGE_CACHE
    with tempfile.TemporaryDirectory() as tmp:
        paths.IMAGE_CACHE = pathlib.Path(tmp) / "reposcan" / "images.json"
        try:
            yield
        finally:
            paths.IMAGE_CACHE = saved


def test_records_and_reads_back_identities() -> None:
    with _isolated():
        # nothing recorded yet
        assert cache.find_recorded_identity("reposcan:x") is None
        cache.record("reposcan:x", "sha256:abc")
        cache.record("reposcan:y", "sha256:def")  # a second entry coexists
        assert cache.find_recorded_identity("reposcan:x") == "sha256:abc"
        assert cache.find_recorded_identity("reposcan:y") == "sha256:def"


def test_a_malformed_cache_reads_as_empty() -> None:
    with _isolated():
        path = paths.IMAGE_CACHE
        path.parent.mkdir(parents=True)
        path.write_text("{ not json")
        assert cache.find_recorded_identity("reposcan:x") is None  # ignored, not fatal


def test_load_returns_all_records_and_remove_drops_one() -> None:
    with _isolated():
        assert cache.load() == {}
        cache.record("reposcan:x", "sha256:abc")
        cache.record("ghcr.io/acme/thing:latest", "sha256:def")
        assert cache.load() == {
            "reposcan:x": "sha256:abc",
            "ghcr.io/acme/thing:latest": "sha256:def",
        }
        assert cache.remove("reposcan:x") is True  # present, removed
        assert cache.find_recorded_identity("reposcan:x") is None
        assert cache.remove("reposcan:x") is False  # already gone


def test_clear_empties_the_cache() -> None:
    with _isolated():
        cache.record("reposcan:x", "sha256:abc")
        assert cache.clear() is None
        assert cache.load() == {}
        assert cache.clear() is None  # already empty: still fine

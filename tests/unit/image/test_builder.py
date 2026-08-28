# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the shared image ensure step (reposcan.image.builder).

ensure_image is the trust boundary: it rebuilds unless the present image's hash
matches the identity recorded at its last build. A fake builder scripts the present
identity and build result; the identity cache is isolated to a temp XDG_DATA_HOME.
"""

import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager

from reposcan.image.build_spec import BuildSpec
from reposcan.image.builder import ensure_image

_SPEC = BuildSpec("ubuntu:24.04", "/opt/reposcan", "#!/bin/sh\ntrue\n")


@contextmanager
def _isolated_cache() -> Iterator[None]:
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


class _FakeBuilder:
    """An ImageBuilder whose present identity and builds are scripted. A build makes
    the image report identity "built-id"."""

    name = "fake"

    def __init__(self, *, identity: str | None) -> None:
        self._id = identity  # identity currently reported, None if absent
        self.builds = 0

    def reference(self, spec: BuildSpec) -> str:
        return "img:abc"

    def identity(self, reference: str) -> str | None:
        return self._id

    def build(self, spec: BuildSpec) -> str:
        self.builds += 1
        self._id = "built-id"
        return "img:abc"


def test_a_missing_image_is_built_recorded_and_then_reused() -> None:
    with _isolated_cache():
        builder = _FakeBuilder(identity=None)
        assert ensure_image(builder, _SPEC) == "img:abc"
        assert builder.builds == 1  # built because absent, identity recorded
        assert ensure_image(builder, _SPEC) == "img:abc"
        assert builder.builds == 1  # verified against the record, reused


def test_rebuilds_when_the_image_is_unverified_or_forced() -> None:
    with _isolated_cache():
        builder = _FakeBuilder(identity=None)
        ensure_image(builder, _SPEC)  # builds, records "built-id"
        builder._id = "tampered"  # present hash no longer matches the record
        assert ensure_image(builder, _SPEC) == "img:abc"
        assert builder.builds == 2  # rebuilt: present hash != recorded identity
        assert ensure_image(builder, _SPEC, force=True) == "img:abc"
        assert builder.builds == 3  # force rebuilds even a now-verified image

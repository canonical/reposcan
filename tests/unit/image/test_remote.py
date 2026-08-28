# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for using a configured remote image."""

import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager

from reposcan.execution.process import Failure
from reposcan.image.remote import ensure_pulled


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


class _FakePuller:
    """An ImagePuller whose pull result and pulled image id are scripted. Each pull
    reports the current `identity`, so a test can move the tag by changing it.

    With `present` (default True), `identity` reports the image as present from the
    start (the local fast path), so a digest ref skips the pull. Set False and the
    image is absent until `pull` runs, then present -- mirroring a real pull."""

    name = "fake"

    def __init__(
        self,
        *,
        identity: str | None,
        pull_error: Failure | None = None,
        present: bool = True,
    ):
        self._id = identity
        self._pull_error = pull_error
        self._present = present
        self.pulls = 0

    def pull(self, ref: str) -> Failure | None:
        self.pulls += 1
        self._present = True  # a successful pull makes the image present
        return self._pull_error

    def identity(self, ref: str) -> str | None:
        return self._id if self._present else None


def test_a_tag_is_pinned_on_first_use_then_reused_while_unchanged() -> None:
    with _isolated_cache():
        puller = _FakePuller(identity="sha256:aaa", present=False)
        ref = "ghcr.io/acme/thing:latest"
        assert ensure_pulled(puller, ref) == ref  # first use records the id
        assert ensure_pulled(puller, ref) == ref  # same id, reused
        assert puller.pulls == 2  # pulled each time; trusted from the record


def test_a_moved_tag_is_refused() -> None:
    with _isolated_cache():
        puller = _FakePuller(identity="sha256:aaa", present=False)
        ref = "ghcr.io/acme/thing:latest"
        assert ensure_pulled(puller, ref) == ref  # pins to sha256:aaa
        puller._id = "sha256:bbb"  # the tag now points at a different image
        result = ensure_pulled(puller, ref)
        assert isinstance(result, Failure)
        assert "changed since first use" in result.reason


def test_a_digest_pinned_ref_is_trusted_without_a_record() -> None:
    with _isolated_cache():
        puller = _FakePuller(identity="sha256:aaa")
        ref = "ghcr.io/acme/thing@sha256:" + "a" * 64
        assert ensure_pulled(puller, ref) == ref
        # The image is verified local on first call (identity is present), so no pull.
        assert puller.pulls == 0
        puller._id = "sha256:bbb"  # a differing id never matters for a digest ref
        assert ensure_pulled(puller, ref) == ref
        assert puller.pulls == 0  # still local, still no pull


def test_pull_and_missing_image_failures_are_returned() -> None:
    with _isolated_cache():
        failed = _FakePuller(
            identity=None, pull_error=Failure(reason="no network"), present=False
        )
        assert isinstance(ensure_pulled(failed, "x:1"), Failure)
        # Pull "succeeds" but the image is still not present: present stays False.
        vanished = _FakePuller(identity=None, present=False)
        vanished.pull = lambda ref: None  # type: ignore[assignment]  # pull succeeds
        result = ensure_pulled(vanished, "x:1")
        assert isinstance(result, Failure) and "not present after pull" in result.reason


def test_a_digest_pinned_ref_not_present_locally_is_pulled() -> None:
    # When the image is absent locally, the fast path declines and the pull runs.
    with _isolated_cache():
        puller = _FakePuller(identity="sha256:aaa", present=False)
        ref = "ghcr.io/acme/thing@sha256:" + "a" * 64
        assert ensure_pulled(puller, ref) == ref  # present after the pull
        assert puller.pulls == 1


def test_a_digest_pinned_ref_absent_after_pull_fails() -> None:
    # Pull "succeeds" but the image is still not inspectable -> a Failure, not a
    # fall-through to a stale local state.
    with _isolated_cache():
        puller = _FakePuller(identity=None, present=False)
        ref = "ghcr.io/acme/thing@sha256:" + "a" * 64
        result = ensure_pulled(puller, ref)
        assert isinstance(result, Failure)
        assert "not present after pull" in result.reason


def test_a_tag_ref_is_always_pulled_even_when_local() -> None:
    # A tag can move on the registry, so it is always pulled to re-confirm -- the
    # local fast path is digest-only.
    with _isolated_cache():
        puller = _FakePuller(identity="sha256:aaa")
        ref = "ghcr.io/acme/thing:latest"  # not digest-pinned
        assert ensure_pulled(puller, ref) == ref
        assert puller.pulls == 1

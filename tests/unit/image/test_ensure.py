# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for reposcan.image.ensure."""

import pathlib
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager

import reposcan.image.docker as docker
from reposcan import paths
from reposcan.execution.process import ExecResult
from reposcan.image.docker import DockerImageBuilder
from reposcan.image.ensure import ensure_built, ensure_pulled
from reposcan.image.spec import BuildSpec
from reposcan.result import Err, Result

_SPEC = BuildSpec("ubuntu:24.04", "/opt/reposcan", "#!/bin/sh\ntrue\n")


@contextmanager
def _isolated_cache() -> Iterator[None]:
    saved = paths.IMAGE_CACHE
    with tempfile.TemporaryDirectory() as tmp:
        paths.IMAGE_CACHE = pathlib.Path(tmp) / "reposcan" / "images.json"
        try:
            yield
        finally:
            paths.IMAGE_CACHE = saved


class _FakeBuilder(DockerImageBuilder):
    """A DockerImageBuilder whose identity and builds are scripted.

    A build makes the image report identity "built-id".
    """

    name = "fake"

    def __init__(self, *, identity: str | None) -> None:
        self._id = identity  # identity currently reported, None if absent
        self.builds = 0

    def derive_reference(self, spec: BuildSpec) -> str:
        return "img:abc"

    def read_identity(self, reference: str) -> str | None:
        return self._id

    def build(self, spec: BuildSpec) -> Result[str]:
        self.builds += 1
        self._id = "built-id"
        return "img:abc"


class _FakeDocker:
    """Stands in for the docker CLI, answering `pull` and `image inspect`.

    `identity` is what an inspect reports once the image is present. With
    `present=False` the image is absent until a pull runs, mirroring a real pull; a
    test moves a tag by reassigning `identity`.
    """

    def __init__(
        self,
        *,
        identity: str | None,
        present: bool = True,
        pull_error: Err | None = None,
    ) -> None:
        self.identity = identity
        self.present = present
        self.pull_error = pull_error
        self.pulls = 0

    def __call__(self, command: Sequence[str], **kwargs: object) -> Result[ExecResult]:
        argv = list(command)
        if argv[:2] == ["docker", "pull"]:
            self.pulls += 1
            if self.pull_error is not None:
                return self.pull_error
            self.present = True
            return ExecResult(0, "", "")
        if argv[:3] == ["docker", "image", "inspect"]:
            if not self.present or self.identity is None:
                return Err("No such image")
            return ExecResult(0, f"{self.identity}\n", "")
        raise AssertionError(f"unexpected command: {argv}")


@contextmanager
def _docker(fake: _FakeDocker) -> Iterator[_FakeDocker]:
    """Run the pull path against `fake` instead of the real docker CLI."""
    saved = docker.run_process
    docker.run_process = fake
    try:
        yield fake
    finally:
        docker.run_process = saved


def test_a_build_is_reused_until_its_identity_stops_matching() -> None:
    with _isolated_cache():
        builder = _FakeBuilder(identity=None)
        assert ensure_built(builder, _SPEC) == "img:abc"
        assert builder.builds == 1  # built because absent, identity recorded
        assert ensure_built(builder, _SPEC) == "img:abc"
        assert builder.builds == 1  # verified against the record, reused
        builder._id = "tampered"  # present hash no longer matches the record
        assert ensure_built(builder, _SPEC) == "img:abc"
        assert builder.builds == 2  # rebuilt: present hash != recorded identity
        assert ensure_built(builder, _SPEC, force=True) == "img:abc"
        assert builder.builds == 3  # force rebuilds even a now-verified image


def test_a_tag_is_pinned_on_first_use_and_refused_once_it_moves() -> None:
    with (
        _isolated_cache(),
        _docker(_FakeDocker(identity="sha256:aaa", present=False)) as docker,
    ):
        ref = "ghcr.io/acme/thing:latest"
        assert ensure_pulled(ref) == ref  # first use records the id
        assert ensure_pulled(ref) == ref  # same id, reused
        # A tag can move on the registry, so it is pulled every time to re-confirm:
        # the local fast path is digest-only.
        assert docker.pulls == 2
        docker.identity = "sha256:bbb"  # the tag now points at a different image
        moved = ensure_pulled(ref)
        assert isinstance(moved, Err)
        assert "changed since first use" in moved.msg


def test_a_digest_ref_is_pulled_once_then_trusted_locally() -> None:
    with (
        _isolated_cache(),
        _docker(_FakeDocker(identity="sha256:aaa", present=False)) as docker,
    ):
        ref = "ghcr.io/acme/thing@sha256:" + "a" * 64
        assert ensure_pulled(ref) == ref  # absent, so the fast path declines
        assert docker.pulls == 1
        docker.identity = "sha256:bbb"  # a differing id never matters for a digest ref
        assert ensure_pulled(ref) == ref  # present now: verified locally, no pull
        assert docker.pulls == 1


def test_pull_failures_are_returned() -> None:
    ref = "ghcr.io/acme/thing@sha256:" + "a" * 64
    unreachable = _FakeDocker(
        identity=None, present=False, pull_error=Err("no network")
    )
    with _isolated_cache(), _docker(unreachable):
        failed = ensure_pulled(ref)
        assert isinstance(failed, Err) and "no network" in failed.msg
    # The pull "succeeds" but the image is still not inspectable: a Err, not a
    # fall-through to a stale local state.
    with _isolated_cache(), _docker(_FakeDocker(identity=None, present=False)):
        vanished = ensure_pulled(ref)
        assert isinstance(vanished, Err)
        assert "not present after pull" in vanished.msg

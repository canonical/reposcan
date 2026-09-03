# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for backend selection (reposcan.backends).

Availability is controlled by patching backends.run_process (the liveness probe);
local is always available. `select_backend` takes an already-resolved backend name
(env/config precedence happens upstream, in parameter resolution).
"""

import os
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager

import reposcan.backends as backends
from reposcan.backends import (
    Backend,
    DockerBackend,
    LocalBackend,
    LxdBackend,
    _tool_image_for,
    select_backend,
    start_session,
)
from reposcan.execution.local import LocalContext
from reposcan.execution.process import ExecResult, Failure
from reposcan.image.remote import CANONICAL_REF
from reposcan.paths import tools_root


@contextmanager
def _availability(*, lxd_ok: bool, docker_ok: bool) -> Iterator[None]:
    ok = ExecResult(0, "", "")

    def fake(
        command: Sequence[str],
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float | None = None,
        check: bool = False,
    ) -> ExecResult | Failure:
        if command[0] == "lxc":
            return ok if lxd_ok else Failure(reason="no lxc")
        if command[0] == "docker":
            return ok if docker_ok else Failure(reason="no docker")
        return ok

    saved = backends.run_process
    backends.run_process = fake
    try:
        yield
    finally:
        backends.run_process = saved


def _backend(requested: str | None) -> Backend:
    chosen = select_backend(requested)
    assert not isinstance(chosen, Failure), chosen
    return chosen


def test_auto_selects_the_first_available_in_precedence_order() -> None:
    with _availability(lxd_ok=True, docker_ok=True):
        assert _backend("auto").name == "docker"
    with _availability(lxd_ok=True, docker_ok=False):
        assert _backend("auto").name == "lxd"
    with _availability(lxd_ok=False, docker_ok=False):
        assert _backend("auto").name == "local"  # always available, the last resort


def test_select_backend_honours_the_resolved_name_and_treats_none_as_auto() -> None:
    # An explicit resolved name selects exactly that backend.
    with _availability(lxd_ok=True, docker_ok=True):
        assert _backend("local").name == "local"
        assert _backend("docker").name == "docker"
    # None means auto: the first available in precedence order.
    with _availability(lxd_ok=False, docker_ok=True):
        assert _backend(None).name == "docker"


def test_invalid_selections_are_failures() -> None:
    assert isinstance(select_backend("bogus"), Failure)  # unknown name
    with _availability(lxd_ok=False, docker_ok=False):
        failure = select_backend("docker")  # explicit but unavailable
    assert isinstance(failure, Failure) and "docker" in failure.reason


def test_resolved_parent_is_the_image_dir_for_containers_and_a_cache_for_local() -> (
    None
):
    assert DockerBackend().get_resolved_parent() == "/resolved-deps"
    assert LxdBackend().get_resolved_parent() == "/resolved-deps"
    saved = os.environ.get("XDG_CACHE_HOME")
    os.environ["XDG_CACHE_HOME"] = "/tmp/xdg-cache"
    try:
        local = LocalBackend().get_resolved_parent()
    finally:
        if saved is None:
            del os.environ["XDG_CACHE_HOME"]
        else:
            os.environ["XDG_CACHE_HOME"] = saved
    assert local == "/tmp/xdg-cache/reposcan/resolved"


def test_the_image_is_built_for_image_build_and_a_backend_that_cannot_pull() -> None:
    def build_ok(builder: object, spec: object, *, force: bool = False) -> str:
        return "reposcan:tools"

    def build_fail(builder: object, spec: object, *, force: bool = False) -> Failure:
        return Failure(reason="build failed")

    saved = backends.ensure_built
    try:
        backends.ensure_built = build_ok
        assert (
            _tool_image_for(DockerBackend(), "build", tool_image=True)
            == "reposcan:tools"
        )
        # LXD cannot pull yet, so a configured image still builds locally.
        assert (
            _tool_image_for(LxdBackend(), "canonical", tool_image=True)
            == "reposcan:tools"
        )
        backends.ensure_built = build_fail
        assert isinstance(
            _tool_image_for(DockerBackend(), "build", tool_image=True), Failure
        )
    finally:
        backends.ensure_built = saved


def test_the_configured_or_canonical_image_is_pulled_when_the_backend_can() -> None:
    def pull_ok(puller: object, ref: str) -> str:
        return f"pulled:{ref}"

    def pull_fail(puller: object, ref: str) -> Failure:
        return Failure(reason="pull failed")

    saved = backends.ensure_pulled
    try:
        backends.ensure_pulled = pull_ok
        # Unset and the `canonical` shorthand both resolve to the pinned image.
        assert (
            _tool_image_for(DockerBackend(), None, tool_image=True)
            == f"pulled:{CANONICAL_REF}"
        )
        assert (
            _tool_image_for(DockerBackend(), "canonical", tool_image=True)
            == f"pulled:{CANONICAL_REF}"
        )
        # A configured pull is honoured even when the tool image is not requested, so
        # the bootstrap path gets the image rather than a plain base container.
        assert (
            _tool_image_for(DockerBackend(), "canonical", tool_image=False)
            == f"pulled:{CANONICAL_REF}"
        )
        # Without one, tool_image=False is a plain base container: no reference.
        assert _tool_image_for(DockerBackend(), "build", tool_image=False) is None
        backends.ensure_pulled = pull_fail
        result = _tool_image_for(DockerBackend(), None, tool_image=True)
        assert isinstance(result, Failure)
        assert "--image build" in result.reason  # names the alternative
    finally:
        backends.ensure_pulled = saved


def test_start_session_reports_the_local_mount_target() -> None:
    # Local runs the source in place, so the session's target is the source itself.
    with start_session(
        "local", tool_image=True, mount_source="/host/acme-api"
    ) as session:
        assert session.ok
        assert session.target == "/host/acme-api"


def test_start_session_runs_on_the_started_context_or_reports_a_bad_backend() -> None:
    # Local is always available and needs no image, so the session runs on the host.
    with start_session("local", tool_image=True) as session:
        assert session.ok and session.exit_code == 0
        assert isinstance(session.context, LocalContext)
        assert session.tool_root == str(tools_root())
    # An unusable backend yields a not-ok session carrying the exit code.
    with start_session("bogus", tool_image=True) as session:
        assert not session.ok and session.exit_code == 2

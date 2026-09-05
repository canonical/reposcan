# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for backend selection (reposcan.backends).

Backend availability is controlled by patching backends.run_process (the probe);
local is always available. `select_backend` takes an already-resolved backend name
(env/config precedence happens upstream, in parameter resolution).
"""

from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import replace

import reposcan.backends as backends
from reposcan import paths
from reposcan.backends import (
    BACKENDS,
    Backend,
    _provision_image,
    select_backend,
    start_session,
)
from reposcan.execution.local import LocalContext
from reposcan.execution.process import ExecResult
from reposcan.image.spec import CANONICAL_REF
from reposcan.result import Err, Result


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
    ) -> Result[ExecResult]:
        if command[0] == "lxc":
            return ok if lxd_ok else Err("no lxc")
        if command[0] == "docker":
            return ok if docker_ok else Err("no docker")
        return ok

    saved = backends.run_process
    backends.run_process = fake
    try:
        yield
    finally:
        backends.run_process = saved


def _pick_backend(requested: str | None) -> Backend:
    chosen = select_backend(requested)
    assert not isinstance(chosen, Err), chosen.msg
    return chosen


def test_auto_selects_the_first_available_in_precedence_order() -> None:
    with _availability(lxd_ok=True, docker_ok=True):
        assert _pick_backend("auto").name == "docker"
    with _availability(lxd_ok=True, docker_ok=False):
        assert _pick_backend("auto").name == "lxd"
    with _availability(lxd_ok=False, docker_ok=False):
        assert (
            _pick_backend("auto").name == "local"
        )  # always available, the last resort


def test_select_backend_honours_the_resolved_name_and_treats_none_as_auto() -> None:
    # An explicit resolved name selects exactly that backend.
    with _availability(lxd_ok=True, docker_ok=True):
        assert _pick_backend("local").name == "local"
        assert _pick_backend("docker").name == "docker"
    # None means auto: the first available in precedence order.
    with _availability(lxd_ok=False, docker_ok=True):
        assert _pick_backend(None).name == "docker"


def test_invalid_selections_are_failures() -> None:
    assert isinstance(select_backend("bogus"), Err)  # unknown name
    with _availability(lxd_ok=False, docker_ok=False):
        failure = select_backend("docker")  # explicit but unavailable
    assert isinstance(failure, Err) and "docker" in failure.msg


def test_the_image_is_built_for_image_build_and_a_backend_that_cannot_pull() -> None:
    def build_ok(builder: object, spec: object, *, force: bool = False) -> Result[str]:
        return "reposcan:tools"

    def build_fail(
        builder: object, spec: object, *, force: bool = False
    ) -> Result[str]:
        return Err("build failed")

    saved = backends.ensure_built
    try:
        backends.ensure_built = build_ok
        assert _provision_image(BACKENDS["docker"], "build") == "reposcan:tools"
        # LXD cannot pull yet, so a configured image still builds locally.
        assert _provision_image(BACKENDS["lxd"], "canonical") == "reposcan:tools"
        backends.ensure_built = build_fail
        assert isinstance(_provision_image(BACKENDS["docker"], "build"), Err)
    finally:
        backends.ensure_built = saved


def test_the_configured_or_canonical_image_is_pulled_when_the_backend_can() -> None:
    def pull_ok(ref: str) -> Result[str]:
        return f"pulled:{ref}"

    def pull_fail(ref: str) -> Result[str]:
        return Err("pull failed")

    docker = replace(BACKENDS["docker"], puller=pull_ok)
    pinned = f"pulled:{CANONICAL_REF}"
    # Unset and the `canonical` shorthand both resolve to the pinned image.
    assert _provision_image(docker, None) == pinned
    assert _provision_image(docker, "canonical") == pinned

    result = _provision_image(replace(docker, puller=pull_fail), None)
    assert isinstance(result, Err)
    assert "--image build" in result.msg  # names the alternative


def test_start_session_reports_the_local_mount_target() -> None:
    # Local runs the source in place, so the session's target is the source itself.
    with start_session("local", mount_source="/host/acme-api") as session:
        assert session.ok
        assert session.target == "/host/acme-api"


def test_start_session_runs_on_the_started_context_or_reports_a_bad_backend() -> None:
    # Local is always available and needs no image, so the session runs on the host.
    with start_session("local") as session:
        assert session.ok and session.exit_code == 0
        assert isinstance(session.context, LocalContext)
        assert session.install_dir == str(paths.TOOL_INSTALL_DIR)
    # An unusable backend yields a not-ok session carrying the exit code.
    with start_session("bogus") as session:
        assert not session.ok and session.exit_code == 2

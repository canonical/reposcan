# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the LXD execution context and project (reposcan.execution.lxd).

lxc is not invoked: run_process is patched with a fake that records the argv.
"""

from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager

import reposcan.execution.lxd as lxd
from reposcan.execution.context import RunUser
from reposcan.execution.lxd import LxdContext, ensure_project
from reposcan.execution.process import ExecResult, Failure


@contextmanager
def _patched_run(result: ExecResult | Failure):
    calls: list[list[str]] = []

    def fake(
        command: Sequence[str],
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float | None = None,
        stream_stdout: bool = False,
        stream_stderr: bool = False,
        stdin: str | None = None,
    ) -> ExecResult | Failure:
        calls.append(list(command))
        return result

    # start() calls ensure_project (which would shell out to lxc); stub it to a no-op
    # here. ensure_project's own behavior is covered by the tests further down.
    saved_run, saved_ensure = lxd.run_process, lxd.ensure_project
    lxd.run_process = fake
    lxd.ensure_project = lambda: None
    try:
        yield calls
    finally:
        lxd.run_process = saved_run
        lxd.ensure_project = saved_ensure


@contextmanager
def _patched_responses(respond: Callable[[list[str]], ExecResult | Failure]):
    """Patch run_process with a fake whose reply depends on the argv, for exercising
    ensure_project directly (which really calls run_process, not a stub)."""
    calls: list[list[str]] = []

    def fake(
        command: Sequence[str],
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float | None = None,
        check: bool = False,
        stream_stdout: bool = False,
        stream_stderr: bool = False,
        stdin: str | None = None,
    ) -> ExecResult | Failure:
        calls.append(list(command))
        return respond(list(command))

    saved = lxd.run_process
    lxd.run_process = fake
    try:
        yield calls
    finally:
        lxd.run_process = saved


def test_launches_the_given_image_and_execs_commands_in_it() -> None:
    with _patched_run(ExecResult(0, "", "")) as calls:
        ctx = LxdContext("reposcan-tools")
        assert ctx.start() is None
        assert ctx._instance_name is not None
        # Every lxc command is pinned to reposcan's own project, not `default`.
        assert calls[-1][:4] == ["lxc", "--project", "reposcan", "launch"]
        assert "--ephemeral" in calls[-1]
        assert "reposcan-tools" in calls[-1]  # launched from the given image
        ctx.run(["ls"], cwd="/src", env={"K": "V"})
    name = ctx._instance_name
    expected = ["lxc", "--project", "reposcan", "exec", name]
    expected += ["--cwd", "/src", "--env", "K=V", "--", "ls"]
    assert calls[-1] == expected


def test_a_user_drops_privileges_via_setpriv() -> None:
    # The context's default identity (set at construction) wraps every command in
    # setpriv --reuid/--regid with --clear-groups when it has no supplementary groups;
    # the scan user's home is set for tool caches.
    with _patched_responses(lambda argv: ExecResult(0, "", "")) as calls:
        ctx = LxdContext("reposcan-tools", user=RunUser(10000, 10000, ()))
        assert ctx.start() is None
        ctx.run(["trivy", "fs", "."], cwd="/scan/acme")
    exec_argv = calls[-1]
    assert "HOME=/home/reposcan" in exec_argv  # the scan user's home for tool caches
    assert "setpriv" in exec_argv and "--reuid=10000" in exec_argv  # dropped to the uid
    assert "--regid=10000" in exec_argv
    assert "--clear-groups" in exec_argv  # no supplementary groups -> cleared
    assert "--init-groups" not in exec_argv  # no /etc/group lookup
    assert exec_argv[-3:] == ["trivy", "fs", "."]  # the real command, after setpriv --


def test_start_maps_the_default_user_via_a_per_instance_idmap() -> None:
    # A non-root default user gets a per-instance raw.idmap (both uid+gid, plus each
    # supplementary gid) set on launch, so LXD represents the host uid in the
    # container's shifted namespace. Root and an unset user get no idmap.
    user = RunUser(1000, 1000, (1000, 42, 100))  # primary already in `both`; one dup
    with _patched_responses(lambda argv: ExecResult(0, "", "")) as calls:
        ctx = LxdContext("reposcan-tools", user=user)
        assert ctx.start() is None
    launch = next(
        c for c in calls if c[:4] == ["lxc", "--project", "reposcan", "launch"]
    )
    idx = launch.index("--config")
    blob = launch[idx + 1]
    assert blob.startswith("raw.idmap=")
    lines = blob[len("raw.idmap=") :].split("\n")
    assert lines[0] == "both 1000 1000"  # uid and primary gid mapped in one line
    assert "gid 42 42" in lines and "gid 100 100" in lines  # supplementary gids
    assert "gid 1000 1000" not in lines  # primary gid not duplicated
    # Root and an unset user get no idmap (root is already in the default map).
    for no_idmap_user in (RunUser(0, 0, ()), None):
        with _patched_responses(lambda argv: ExecResult(0, "", "")) as calls:
            ctx = LxdContext("reposcan-tools", user=no_idmap_user)
            assert ctx.start() is None
        launch = next(
            c for c in calls if c[:4] == ["lxc", "--project", "reposcan", "launch"]
        )
        assert "--config" not in launch  # no idmap for root / unset


def test_mounts_the_source_read_only_keeping_its_name() -> None:
    # respond ok to every lxc call (project present, launch, device add).
    with _patched_responses(lambda argv: ExecResult(0, "", "")) as calls:
        ctx = LxdContext("reposcan-tools", mount_source="/host/acme-api")
        assert ctx.start() is None
    device_add = next(c for c in calls if c[3:6] == ["config", "device", "add"])
    assert "source=/host/acme-api" in device_add
    assert "path=/scan/acme-api" in device_add  # name preserved
    assert "readonly=true" in device_add


def test_ensure_project_leaves_an_existing_project_alone() -> None:
    # `lxc project show` succeeds -> the project is there -> no create, no failure.
    present = ExecResult(0, "name: reposcan\n", "")
    with _patched_responses(lambda argv: present) as calls:
        assert ensure_project() is None
    assert calls == [["lxc", "project", "show", "reposcan"]]


def test_ensure_project_creates_a_missing_project_isolating_images() -> None:
    # `lxc project show` fails -> create it with the isolating features.
    def respond(argv: list[str]) -> ExecResult | Failure:
        if argv[:3] == ["lxc", "project", "show"]:
            return ExecResult(1, "", "not found")
        return ExecResult(0, "", "")

    with _patched_responses(respond) as calls:
        assert ensure_project() is None
    create = calls[-1]
    assert create[:4] == ["lxc", "project", "create", "reposcan"]
    assert "features.images=true" in create  # tool image stays out of `default`
    assert "features.profiles=false" in create  # borrow default's working profile


def test_ensure_project_returns_a_failed_create_as_a_failure() -> None:
    def respond(argv: list[str]) -> ExecResult | Failure:
        if argv[:3] == ["lxc", "project", "show"]:
            return ExecResult(1, "", "not found")
        return Failure(reason="permission denied")

    with _patched_responses(respond):
        result = ensure_project()
    assert isinstance(result, Failure) and result.reason == "permission denied"

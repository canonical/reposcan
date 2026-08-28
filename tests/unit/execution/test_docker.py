# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the Docker execution context (reposcan.execution.docker).

docker is not invoked: run_process is patched with a fake that records the argv.
"""

from collections.abc import Mapping, Sequence
from contextlib import contextmanager

import reposcan.execution.docker as docker
from reposcan.execution.context import RunUser
from reposcan.execution.docker import DockerContext
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

    saved = docker.run_process
    docker.run_process = fake
    try:
        yield calls
    finally:
        docker.run_process = saved


def test_starts_the_given_image_and_execs_commands_in_it() -> None:
    with _patched_run(ExecResult(0, "abc123\n", "")) as calls:
        ctx = DockerContext("reposcan:tools")
        assert ctx.start() is None
        assert ctx._instance_name == "abc123"  # container id from `docker run`
        assert "reposcan:tools" in calls[-1]  # started from the given image
        ctx.run(["ls", "-a"], cwd="/src", env={"K": "V"})
    expected = ["docker", "exec", "-w", "/src", "-e", "K=V", "abc123", "ls", "-a"]
    assert calls[-1] == expected


def test_stdin_keeps_the_exec_interactive() -> None:
    # docker exec discards stdin unless -i is passed; the context adds it only then.
    with _patched_run(ExecResult(0, "", "")) as calls:
        ctx = DockerContext("reposcan:tools")
        assert ctx.start() is None
        ctx.run(["cp", "/dev/stdin", "out.txt"], cwd="/scan", stdin="data")
    assert calls[-1][:3] == ["docker", "exec", "-i"]


def test_a_user_drops_privileges_via_setpriv() -> None:
    # The context's default identity (set at construction) wraps every command in
    # setpriv --reuid/--regid with --clear-groups when it has no supplementary groups
    # (setpriv keeps the caller's groups by default, which would leak root's groups
    # to the dropped user).
    with _patched_run(ExecResult(0, "abc123\n", "")) as calls:
        ctx = DockerContext("reposcan:tools", user=RunUser(10000, 10000, ()))
        assert ctx.start() is None
        ctx.run(["trivy", "fs", "."], cwd="/scan/acme")
    exec_argv = calls[-1]
    assert "HOME=/home/reposcan" in exec_argv  # the scan user's home for tool caches
    assert "setpriv" in exec_argv and "--reuid=10000" in exec_argv  # dropped to the uid
    assert "--regid=10000" in exec_argv
    assert "--clear-groups" in exec_argv  # no supplementary groups -> cleared
    assert "--init-groups" not in exec_argv  # no /etc/group lookup
    assert exec_argv[-3:] == ["trivy", "fs", "."]  # the real command, after setpriv --


def test_run_without_a_default_user_runs_as_root() -> None:
    # A context built with no user runs as root: no setpriv, no HOME override.
    with _patched_run(ExecResult(0, "abc123\n", "")) as calls:
        ctx = DockerContext("reposcan:tools")
        assert ctx.start() is None
        ctx.run(["ls"])
    exec_argv = calls[-1]
    assert "setpriv" not in exec_argv
    assert not any(a.startswith("HOME=") for a in exec_argv)


def test_run_user_override_runs_as_that_identity_for_one_call() -> None:
    # An explicit `user` on .run overrides the context's default for that call only.
    with _patched_run(ExecResult(0, "abc123\n", "")) as calls:
        ctx = DockerContext("reposcan:tools")  # default: root
        assert ctx.start() is None
        ctx.run(["ls"], user=RunUser(1000, 1000, (42,)))
    exec_argv = calls[-1]
    assert "--reuid=1000" in exec_argv and "--regid=1000" in exec_argv
    assert "--groups=42" in exec_argv  # supplementary group set on the override
    assert "HOME=/tmp" in exec_argv  # non-scan uid -> /tmp home


def test_mounts_the_source_read_only_keeping_its_name() -> None:
    with _patched_run(ExecResult(0, "abc123\n", "")) as calls:
        ctx = DockerContext("reposcan:tools", mount_source="/host/acme-api")
        assert ctx.start() is None
    run_argv = calls[-1]  # the `docker run` argv
    assert "-v" in run_argv
    mount = run_argv[run_argv.index("-v") + 1]
    assert mount == "/host/acme-api:/scan/acme-api:ro"  # read-only, name preserved

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the LXD image builder (reposcan.image.lxd).

lxc is not invoked: run_process is patched with a fake that records the argv; its
response is a callable so a specific step can be made to fail.
"""

import logging
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager

import reposcan.image.lxd as lxd
from reposcan.execution.process import ExecResult, Failure
from reposcan.image.build_spec import BuildSpec

_SPEC = BuildSpec("ubuntu:24.04", "/opt/reposcan", "#!/bin/sh\ntrue\n")
_BUILDER = lxd.LxdImageBuilder()
_OK = ExecResult(0, "", "")


@contextmanager
def _patched(respond: Callable[[list[str]], ExecResult | Failure]):
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
    ) -> ExecResult | Failure:
        calls.append(list(command))
        return respond(list(command))

    # ensure_project and lxd_bridge_hint shell out to lxc/nft through other modules, so
    # stub them here; their own behavior is covered in test_lxd_context / test_firewall.
    saved_run = lxd.run_process
    saved_ensure = lxd.ensure_project
    saved_hint = lxd.lxd_bridge_hint
    lxd.run_process = fake
    lxd.ensure_project = lambda: None
    lxd.lxd_bridge_hint = lambda: "check the lxdbr0 bridge firewall"
    try:
        yield calls
    finally:
        lxd.run_process = saved_run
        lxd.ensure_project = saved_ensure
        lxd.lxd_bridge_hint = saved_hint


# Every lxc command is pinned to reposcan's own project, not `default`.
_LXC = ["lxc", "--project", "reposcan"]


def test_build_launches_provisions_publishes_and_cleans_up() -> None:
    with _patched(lambda argv: _OK) as calls:
        alias = _BUILDER.build(_SPEC)
    assert alias == f"reposcan-{_SPEC.short_digest}"
    assert isinstance(alias, str) and ":" not in alias  # LXD aliases cannot use a colon
    assert calls[0][:5] == [*_LXC, "image", "delete"]  # clear any stale alias first
    assert calls[1][:4] == [*_LXC, "launch"]
    assert calls[-2][:4] == [*_LXC, "publish"] and "--alias" in calls[-2]
    assert alias in calls[-2]
    assert calls[-1][:4] == [*_LXC, "delete"]  # build container removed last


def test_build_deletes_the_builder_even_when_a_step_fails() -> None:
    # Fail the "run the install script" exec step; the builder must still be deleted.
    def respond(argv: list[str]) -> ExecResult | Failure:
        if "sh" in argv and "/root/install.sh" in argv:
            return Failure(reason="install failed")
        return _OK

    with _patched(respond) as calls:
        result = _BUILDER.build(_SPEC)
    assert isinstance(result, Failure) and result.reason == "install failed"
    assert calls[-1][:4] == [*_LXC, "delete"]


class _RecordingHandler(logging.Handler):
    """Collects the messages logged while it is attached."""

    def __init__(self) -> None:
        super().__init__()
        self.warnings: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        if record.levelno == logging.WARNING:
            self.warnings.append(record.getMessage())


def test_build_aborts_early_and_warns_when_the_container_has_no_network() -> None:
    """The outbound-connectivity probe fails; the build must stop before running the
    install script (no multi-minute doomed download), warn about the firewall cause,
    and still delete the builder."""

    def respond(argv: list[str]) -> ExecResult | Failure:
        if any("/dev/tcp" in arg for arg in argv):  # the connectivity probe
            return ExecResult(1, "", "Network is unreachable")
        return _OK

    handler = _RecordingHandler()
    logger = logging.getLogger("reposcan.image.lxd")
    logger.addHandler(handler)
    try:
        with _patched(respond) as calls:
            result = _BUILDER.build(_SPEC)
    finally:
        logger.removeHandler(handler)

    assert isinstance(result, Failure) and "network" in result.reason.lower()
    assert not any("/root/install.sh" in argv for argv in calls)  # install never ran
    assert calls[-1][:4] == [*_LXC, "delete"]  # builder still cleaned up
    # The firewall warning is emitted (the diagnostic that was previously never shown).
    assert handler.warnings == ["check the lxdbr0 bridge firewall"]


def test_identity_parses_the_fingerprint_or_none_when_absent() -> None:
    info = ExecResult(0, "Architecture: x86_64\nFingerprint: deadbeef\n", "")
    with _patched(lambda argv: info) as calls:
        assert _BUILDER.identity("reposcan-x") == "deadbeef"
    assert calls[0][:5] == [*_LXC, "image", "info"]
    with _patched(lambda argv: ExecResult(1, "", "not found")):
        assert _BUILDER.identity("reposcan-x") is None

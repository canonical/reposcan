# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the in-container identity helpers (reposcan.execution.context)."""

import os

from reposcan.execution.context import RunUser, resolve_env, wrap_with_setpriv


def test_setpriv_with_groups_sets_them_and_drops_init_groups() -> None:
    user = RunUser(1000, 1000, (1000, 42, 100))
    argv = wrap_with_setpriv(["trivy", "fs", "."], user)
    assert argv[0] == "setpriv"
    assert "--reuid=1000" in argv and "--regid=1000" in argv
    assert "--groups=1000,42,100" in argv  # supplementary gids, raw and ordered
    assert "--init-groups" not in argv  # no /etc/group lookup
    assert "--clear-groups" not in argv  # groups present, not cleared
    assert argv[-4:] == ["--", "trivy", "fs", "."]


def test_setpriv_without_groups_clears_them() -> None:
    # setpriv keeps the caller's groups by default, which would leak root's groups
    # to the dropped user; with no supplementary groups they are cleared instead.
    argv = wrap_with_setpriv(["ls"], RunUser(10000, 10000, ()))
    assert "--clear-groups" in argv
    assert "--groups" not in "".join(argv)
    assert argv[-2:] == ["--", "ls"]


def test_resolve_env_takes_a_value_inline_or_from_the_host() -> None:
    os.environ["REPOSCAN_TEST_FORWARDED"] = "from-host"
    try:
        resolved = resolve_env(
            ["NAME=inline", "REPOSCAN_TEST_FORWARDED", "REPOSCAN_TEST_MISSING"]
        )
    finally:
        del os.environ["REPOSCAN_TEST_FORWARDED"]
    # A name the host does not set is dropped rather than passed as empty, so a tool
    # cannot tell it apart from one deliberately set to "".
    assert resolved == {"NAME": "inline", "REPOSCAN_TEST_FORWARDED": "from-host"}


def test_resolve_env_keeps_a_value_containing_an_equals_sign() -> None:
    assert resolve_env(["URL=https://h/?a=1"]) == {"URL": "https://h/?a=1"}

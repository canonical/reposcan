# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the firewall check (reposcan.execution.firewall).

The analyzers are fed nft JSON / iptables -S text directly; build_lxd_bridge_hint is
driven through a patched run_process. Neither nft nor iptables is ever invoked.
"""

import json
from collections.abc import Callable

import reposcan.execution.firewall as firewall
from reposcan.execution.firewall import (
    _analyze_iptables,
    _analyze_nft,
    build_lxd_bridge_hint,
)
from reposcan.execution.process import ExecResult
from reposcan.result import Err, Result, is_err

_FORWARD_DROP = {"chain": {"name": "FORWARD", "policy": "drop"}}


def _build_nft(*objects: dict) -> str:
    return json.dumps({"nftables": list(objects)})


def test_nft_analyzer_warns_on_a_blocked_bridge_and_names_the_cause() -> None:
    accept_policy = {"chain": {"name": "FORWARD", "policy": "accept"}}
    assert _analyze_nft(_build_nft(accept_policy), "lxdbr0") is None  # not dropping
    bridge_accept = {
        "rule": {
            "chain": "FORWARD",
            "expr": [{"match": {"right": "lxdbr0"}}, {"accept": None}],
        }
    }
    assert (
        _analyze_nft(_build_nft(_FORWARD_DROP, bridge_accept), "lxdbr0") is None
    )  # allowed

    docker_rules = _build_nft(_FORWARD_DROP, {"chain": {"name": "DOCKER-USER"}})
    docker = _analyze_nft(docker_rules, "lxdbr0")
    assert is_err(docker) and "caused by Docker" in docker.msg
    assert "nft insert rule ip filter DOCKER-USER iifname lxdbr0 accept" in docker.msg
    ufw_rules = _build_nft(_FORWARD_DROP, {"chain": {"name": "ufw-forward"}})
    ufw = _analyze_nft(ufw_rules, "lxdbr0")
    assert is_err(ufw) and "ufw route allow in on lxdbr0" in ufw.msg
    generic = _analyze_nft(_build_nft(_FORWARD_DROP), "lxdbr0")  # cause unknown
    assert is_err(generic)
    assert "nft insert rule ip filter FORWARD iifname lxdbr0 accept" in generic.msg


def test_iptables_analyzer_mirrors_nft_over_text() -> None:
    assert _analyze_iptables("-P FORWARD ACCEPT\n", "lxdbr0") is None  # not dropping
    allowed = "-P FORWARD DROP\n-A FORWARD -o lxdbr0 -j ACCEPT\n"
    assert _analyze_iptables(allowed, "lxdbr0") is None  # bridge explicitly allowed
    docker = _analyze_iptables(
        "-P FORWARD DROP\n-N DOCKER-USER\n-A FORWARD -j DOCKER-USER\n", "lxdbr0"
    )
    assert is_err(docker) and "caused by Docker" in docker.msg
    assert "iptables -I DOCKER-USER -i lxdbr0 -j ACCEPT" in docker.msg


def _patch_firewall_reader(reader: Callable[[list[str]], Result[ExecResult]]):
    """Point firewall.run_process at `reader` (reply chosen from the argv); returns the
    original to restore in a finally."""
    saved = firewall.run_process

    def fake(command, **_):
        return reader(list(command))

    firewall.run_process = fake
    return saved


def test_bridge_hint_is_specific_when_readable_and_generic_with_nft_otherwise() -> None:
    drop = _build_nft(_FORWARD_DROP, {"chain": {"name": "DOCKER-USER"}})
    readable = _patch_firewall_reader(
        lambda a: ExecResult(0, drop, "") if a[0] == "nft" else Err("x")
    )
    try:
        assert "caused by Docker" in build_lxd_bridge_hint(
            "lxdbr0"
        )  # firewall readable
    finally:
        firewall.run_process = readable

    unreadable = _patch_firewall_reader(lambda a: Err("command not found"))
    try:
        hint = build_lxd_bridge_hint(
            "lxdbr0"
        )  # firewall unreadable -> generic fallback
    finally:
        firewall.run_process = unreadable
    assert "nft insert rule ip filter FORWARD iifname lxdbr0 accept" in hint
    assert "nft insert rule ip filter FORWARD oifname lxdbr0 accept" in hint

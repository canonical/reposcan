# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the firewall check (reposcan.execution.firewall).

The analyzers are fed nft JSON / iptables -S text directly; lxd_bridge_hint is driven
through a patched run_process. Neither nft nor iptables is ever invoked.
"""

import json
from collections.abc import Callable

import reposcan.execution.firewall as firewall
from reposcan.execution.firewall import (
    _analyze_iptables,
    _analyze_nft,
    lxd_bridge_hint,
)
from reposcan.execution.process import ExecResult, Failure

_FORWARD_DROP = {"chain": {"name": "FORWARD", "policy": "drop"}}


def _nft(*objects: dict) -> str:
    return json.dumps({"nftables": list(objects)})


def test_nft_analyzer_warns_on_a_blocked_bridge_and_names_the_cause() -> None:
    accept_policy = {"chain": {"name": "FORWARD", "policy": "accept"}}
    assert _analyze_nft(_nft(accept_policy), "lxdbr0") is None  # not dropping
    bridge_accept = {
        "rule": {
            "chain": "FORWARD",
            "expr": [{"match": {"right": "lxdbr0"}}, {"accept": None}],
        }
    }
    assert _analyze_nft(_nft(_FORWARD_DROP, bridge_accept), "lxdbr0") is None  # allowed

    docker_rules = _nft(_FORWARD_DROP, {"chain": {"name": "DOCKER-USER"}})
    docker = _analyze_nft(docker_rules, "lxdbr0")
    assert docker is not None and "caused by Docker" in docker
    assert "nft insert rule ip filter DOCKER-USER iifname lxdbr0 accept" in docker
    ufw_rules = _nft(_FORWARD_DROP, {"chain": {"name": "ufw-forward"}})
    ufw = _analyze_nft(ufw_rules, "lxdbr0")
    assert ufw is not None and "ufw route allow in on lxdbr0" in ufw
    generic = _analyze_nft(_nft(_FORWARD_DROP), "lxdbr0")  # dropping, cause unknown
    assert generic is not None
    assert "nft insert rule ip filter FORWARD iifname lxdbr0 accept" in generic


def test_iptables_analyzer_mirrors_nft_over_text() -> None:
    assert _analyze_iptables("-P FORWARD ACCEPT\n", "lxdbr0") is None  # not dropping
    allowed = "-P FORWARD DROP\n-A FORWARD -o lxdbr0 -j ACCEPT\n"
    assert _analyze_iptables(allowed, "lxdbr0") is None  # bridge explicitly allowed
    docker = _analyze_iptables(
        "-P FORWARD DROP\n-N DOCKER-USER\n-A FORWARD -j DOCKER-USER\n", "lxdbr0"
    )
    assert docker is not None and "caused by Docker" in docker
    assert "iptables -I DOCKER-USER -i lxdbr0 -j ACCEPT" in docker


def _with_firewall_reader(reader: Callable[[list[str]], ExecResult | Failure]):
    """Point firewall.run_process at `reader` (reply chosen from the argv); returns the
    original to restore in a finally."""
    saved = firewall.run_process

    def fake(command, **_):
        return reader(list(command))

    firewall.run_process = fake
    return saved


def test_bridge_hint_is_specific_when_readable_and_generic_with_nft_otherwise() -> None:
    drop = _nft(_FORWARD_DROP, {"chain": {"name": "DOCKER-USER"}})
    readable = _with_firewall_reader(
        lambda a: ExecResult(0, drop, "") if a[0] == "nft" else Failure(reason="x")
    )
    try:
        assert "caused by Docker" in lxd_bridge_hint("lxdbr0")  # firewall readable
    finally:
        firewall.run_process = readable

    unreadable = _with_firewall_reader(lambda a: Failure(reason="command not found"))
    try:
        hint = lxd_bridge_hint("lxdbr0")  # firewall unreadable -> generic fallback
    finally:
        firewall.run_process = unreadable
    assert "nft insert rule ip filter FORWARD iifname lxdbr0 accept" in hint
    assert "nft insert rule ip filter FORWARD oifname lxdbr0 accept" in hint

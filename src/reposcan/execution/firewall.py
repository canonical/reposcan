# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Warn when the host firewall blocks bridge forwarding, with a cause-aware fix.

Ported from canonical/workshop's CheckBridgeFirewall, extended with an
iptables-legacy fallback. Advisory/logging only.

See: https://documentation.ubuntu.com/lxd/latest/howto/network_bridge_firewalld/
"""

import json
import logging
from typing import Any

from reposcan.execution.process import run_process
from reposcan.result import Err, Result, get_value, is_err

logger = logging.getLogger(__name__)

_DOC = "https://documentation.ubuntu.com/lxd/latest/howto/network_bridge_firewalld/"
_LXD_BRIDGE = "lxdbr0"


def warn_if_lxd_bridge_blocked(bridge: str = _LXD_BRIDGE) -> None:
    """Log a warning if the host firewall blocks forwarding on the LXD bridge.

    Advisory only. Call before every `lxc launch` -- both running a container and
    building an image launch on the bridge and fail the same way when it is blocked.
    """
    if is_err(err := check_firewall(bridge)):
        logger.warning(err.msg)


def build_lxd_bridge_hint(bridge: str = _LXD_BRIDGE) -> str:
    """Explain how to fix an LXD container with no outbound network.

    This always returns a str; it is only called when an issue has been detected and
    the caller needs to generate a message.
    """
    if is_err(err := check_firewall(bridge)):
        return err.msg
    return (
        f"a blocked {bridge} bridge is the usual cause; allow forwarding with: "
        f"sudo nft insert rule ip filter FORWARD iifname {bridge} accept && "
        f"sudo nft insert rule ip filter FORWARD oifname {bridge} accept (see {_DOC})"
    )


def check_firewall(bridge: str) -> Result[None]:
    """Check that the host firewall is forwarding traffic for `bridge`.

    Detection is cause-agnostic: does the FORWARD chain drop by policy, with no rule
    accepting the bridge's traffic? nftables (`nft -j`, structured JSON) is
    authoritative when present; iptables-legacy (`iptables -S`, text) is the fallback
    for hosts without nft.

    Returns:
        None when the bridge is not blocked, and when neither tool's output can be
        read; else an Err naming the cause and the command that fixes it.
    """
    nft = get_value(
        run_process(["nft", "-j", "list", "table", "ip", "filter"], check=True)
    )
    if nft is not None:
        return _analyze_nft(nft.stdout, bridge)
    legacy = get_value(run_process(["iptables", "-S"], check=True))
    if legacy is not None:
        return _analyze_iptables(legacy.stdout, bridge)
    return None


def _analyze_nft(nft_json: str, bridge: str) -> Result[None]:
    """Check `nft -j` JSON for a blocked bridge."""
    try:
        parsed = json.loads(nft_json)
    except json.JSONDecodeError:
        return None
    ruleset: list[Any] = parsed.get("nftables", []) if isinstance(parsed, dict) else []
    if not _has_drop_policy(ruleset):
        return None
    if _has_accept_rule(ruleset, bridge):
        return None
    docker_fix = (
        f"sudo nft insert rule ip filter DOCKER-USER iifname {bridge} accept \\; "
        f"sudo nft insert rule ip filter DOCKER-USER oifname {bridge} "
        "ct state related,established accept"
    )
    return Err(_explain_block(bridge, _classify_cause(ruleset), docker_fix))


def _analyze_iptables(rules: str, bridge: str) -> Result[None]:
    """Check `iptables -S` text for a blocked bridge."""
    lines = [line.strip() for line in rules.splitlines()]
    if "-P FORWARD DROP" not in lines:
        return None
    if any(
        "-j ACCEPT" in line and (f"-i {bridge}" in line or f"-o {bridge}" in line)
        for line in lines
    ):
        return None
    if any("DOCKER" in line for line in lines):
        cause = "docker"
    elif any("ufw" in line for line in lines):
        cause = "ufw"
    else:
        cause = "unknown"
    docker_fix = (
        f"sudo iptables -I DOCKER-USER -i {bridge} -j ACCEPT && "
        f"sudo iptables -I DOCKER-USER -o {bridge} "
        "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
    )
    return Err(_explain_block(bridge, cause, docker_fix))


def _has_drop_policy(ruleset: list[Any]) -> bool:
    """Whether the ruleset's FORWARD chain has a drop policy."""
    for obj in ruleset:
        chain = obj.get("chain") if isinstance(obj, dict) else None
        if chain and chain.get("name") == "FORWARD":
            return chain.get("policy") == "drop"
    return False


def _has_accept_rule(ruleset: list[Any], bridge: str) -> bool:
    """Whether the ruleset has a rule accepting traffic for the bridge."""
    for obj in ruleset:
        rule = obj.get("rule") if isinstance(obj, dict) else None
        if rule is None:
            continue
        expr = json.dumps(rule.get("expr", []))
        if bridge in expr and '"accept"' in expr:
            return True
    return False


def _classify_cause(ruleset: list[Any]) -> str:
    """Classify the drop policy's likely cause: docker, ufw, or unknown."""
    for obj in ruleset:
        if not isinstance(obj, dict):
            continue
        chain = obj.get("chain")
        if chain and "DOCKER" in chain.get("name", ""):
            return "docker"
        rule = obj.get("rule")
        if rule and "ufw" in rule.get("chain", ""):
            return "ufw"
    for obj in ruleset:
        chain = obj.get("chain") if isinstance(obj, dict) else None
        if chain and "ufw" in chain.get("name", ""):
            return "ufw"
    return "unknown"


def _explain_block(bridge: str, cause: str, docker_fix: str) -> str:
    """Explain a blocked bridge and how to unblock it, given its likely cause."""
    base = (
        f"firewall rules may be blocking network traffic on the {bridge} bridge: "
        "the FORWARD chain policy is set to DROP with no rules allowing traffic "
        "through the bridge"
    )
    if cause == "docker":
        return (
            f"{base}. This is likely caused by Docker. To resolve, run: "
            f"{docker_fix} (see {_DOC})"
        )
    if cause == "ufw":
        return (
            f"{base}. This is likely caused by UFW. To resolve, run: "
            f"sudo ufw allow in on {bridge} && sudo ufw route allow in on {bridge} "
            f"&& sudo ufw route allow out on {bridge} (see {_DOC})"
        )
    return (
        f"{base}. To resolve, run: "
        f"sudo nft insert rule ip filter FORWARD iifname {bridge} accept && "
        f"sudo nft insert rule ip filter FORWARD oifname {bridge} accept (see {_DOC})"
    )

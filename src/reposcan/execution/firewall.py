# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Warn when the host firewall blocks bridge forwarding, with a cause-aware fix.

Ported from canonical/workshop's CheckBridgeFirewall, extended with an
iptables-legacy fallback.

Detection is cause-agnostic: is the FORWARD chain policy drop, with no rule that
accepts traffic for the bridge? The remediation is cause-aware: it suggests
Docker-specific, UFW-specific, or generic commands depending on what is found.
nftables (`nft -j`, structured JSON) is authoritative when present; iptables-legacy
(`iptables -S`, text) is a fallback for hosts without nft. Advisory only.

See: https://documentation.ubuntu.com/lxd/latest/howto/network_bridge_firewalld/
"""

import json
import logging
from typing import Any

from reposcan.execution.process import run_process, succeeded

logger = logging.getLogger(__name__)

_DOC = "https://documentation.ubuntu.com/lxd/latest/howto/network_bridge_firewalld/"
_LXD_BRIDGE = "lxdbr0"


def warn_if_lxd_bridge_blocked(bridge: str = _LXD_BRIDGE) -> None:
    """Log a warning if the host firewall blocks forwarding on the LXD bridge.

    Advisory only. Call before every `lxc launch` -- both running a container and
    building an image launch on the bridge and fail the same way when it is blocked.
    """
    warning = firewall_warning(bridge)
    if warning is not None:
        logger.warning(warning)


def lxd_bridge_hint(bridge: str = _LXD_BRIDGE) -> str:
    """Firewall guidance to log when an LXD container has no outbound network.

    Reading nft/iptables needs root privileges that we may not have, and a blocked
    FORWARD chain is the usual culprit. Unlike `firewall_warning`, this never returns
    None: the caller already knows there is a problem and always wants something
    actionable to show.

    Returns:
        str: The specific cause and fix if the host firewall can be read and shows
        `bridge` blocked; otherwise, generic remediation.
    """
    detected = firewall_warning(bridge)
    if detected is not None:
        return detected
    return (
        f"a blocked {bridge} bridge is the usual cause; allow forwarding with: "
        f"sudo nft insert rule ip filter FORWARD iifname {bridge} accept && "
        f"sudo nft insert rule ip filter FORWARD oifname {bridge} accept (see {_DOC})"
    )


def firewall_warning(bridge: str) -> str | None:
    """A warning with a proposed fix if the FORWARD policy drops `bridge`, else None.

    Uses nftables when present, else iptables-legacy; None when neither reports a
    filter FORWARD chain.
    """
    nft = run_process(["nft", "-j", "list", "table", "ip", "filter"])
    if succeeded(nft):
        return _analyze_nft(nft.stdout, bridge)
    legacy = run_process(["iptables", "-S"])
    if succeeded(legacy):
        return _analyze_iptables(legacy.stdout, bridge)
    return None


def _analyze_nft(nft_json: str, bridge: str) -> str | None:
    """Warn from `nft -j` JSON if the bridge is blocked, else None."""
    try:
        parsed = json.loads(nft_json)
    except json.JSONDecodeError:
        return None
    ruleset: list[Any] = parsed.get("nftables", []) if isinstance(parsed, dict) else []
    if not _nft_forward_is_drop(ruleset):
        return None
    if _nft_bridge_accepts(ruleset, bridge):
        return None
    docker_fix = (
        f"sudo nft insert rule ip filter DOCKER-USER iifname {bridge} accept \\; "
        f"sudo nft insert rule ip filter DOCKER-USER oifname {bridge} "
        "ct state related,established accept"
    )
    return _blocked_warning(bridge, _nft_cause(ruleset), docker_fix)


def _analyze_iptables(rules: str, bridge: str) -> str | None:
    """Warn from `iptables -S` text if the bridge is blocked, else None."""
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
    return _blocked_warning(bridge, cause, docker_fix)


def _nft_forward_is_drop(ruleset: list[Any]) -> bool:
    """True if the nft FORWARD chain has a drop policy."""
    for obj in ruleset:
        chain = obj.get("chain") if isinstance(obj, dict) else None
        if chain and chain.get("name") == "FORWARD":
            return chain.get("policy") == "drop"
    return False


def _nft_bridge_accepts(ruleset: list[Any], bridge: str) -> bool:
    """True if an nft rule accepts traffic for the bridge interface."""
    for obj in ruleset:
        rule = obj.get("rule") if isinstance(obj, dict) else None
        if rule is None:
            continue
        expr = json.dumps(rule.get("expr", []))
        if bridge in expr and '"accept"' in expr:
            return True
    return False


def _nft_cause(ruleset: list[Any]) -> str:
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


def _blocked_warning(bridge: str, cause: str, docker_fix: str) -> str:
    """Build the cause-specific warning and remediation for a blocked bridge."""
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

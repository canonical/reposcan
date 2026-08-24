# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""IaC scan fixture: a Dockerfile checkov flags."""

from pathlib import Path

from repo_scanner.scans import sarif
from repo_scanner.scans.iac import IacScan

SCAN = IacScan()


def plant(repo: Path) -> None:
    # A Dockerfile with no USER/HEALTHCHECK and apt without cleanup, so at least one
    # checkov check fails.
    (repo / "Dockerfile").write_text("FROM ubuntu:24.04\nRUN apt-get update\n")


def verify(artifact: sarif.SarifDocument) -> None:
    # checkov flags the Dockerfile: no HEALTHCHECK (CKV_DOCKER_2) and no USER
    # (CKV_DOCKER_3), both located in the planted Dockerfile.
    by_rule = {result.rule_id: result for result in artifact.results()}
    for rule in ("CKV_DOCKER_2", "CKV_DOCKER_3"):
        assert rule in by_rule, f"expected {rule}, got {sorted(by_rule)}"
        assert by_rule[rule].uri.endswith("Dockerfile"), by_rule[rule].uri

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Secrets scan fixture: a committed, non-real AWS key pair for trufflehog to find."""

import subprocess
from pathlib import Path

from repo_scanner.scans import sarif
from repo_scanner.scans.secrets import SecretsScan

SCAN = SecretsScan()


def plant(repo: Path) -> None:
    # A well-formed but non-real AWS key pair, committed so a git-history scan finds
    # it. Not the AWS "EXAMPLE" keys, which trufflehog filters as known placeholders.
    (repo / "config.env").write_text(
        "AWS_ACCESS_KEY_ID=AKIA5B7Q2XLMN3PQRSTU\n"
        "AWS_SECRET_ACCESS_KEY=aBcD1eFgH2iJkL3mNoP4qRsT5uVwX6yZ7A8bC9dE\n"
    )
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "add", "-A")
    _git(
        repo,
        "-c",
        "user.email=f@example.com",
        "-c",
        "user.name=f",
        "commit",
        "-qm",
        "x",
    )


def verify(artifact: sarif.SarifDocument) -> None:
    # trufflehog found the planted AWS key pair, reported in config.env by its AWS
    # detector. The key is non-real so it stays unverified (level "warning").
    results = artifact.results()
    rules = [result.rule_id for result in results]
    aws = [result for result in results if result.rule_id == "AWS"]
    assert aws, f"expected an AWS finding, got rules {rules}"
    assert aws[0].uri.endswith("config.env"), (
        f"{aws[0].uri} does not end with config.env"
    )
    # the detected secret is fingerprinted for reposcan's own cross-run identity
    assert aws[0].result.get("fingerprints", {}).get("secretHash"), (
        f"secret result does not contain secretHash: {aws[0].result}"
    )


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)

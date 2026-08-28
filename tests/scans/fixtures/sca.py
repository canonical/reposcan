# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""SCA scan fixture: a pinned dependency with known CVEs for trivy/grype to report."""

from pathlib import Path

from reposcan.scans import sarif
from reposcan.scans.sca import ScaScan

SCAN = ScaScan()


def plant(repo: Path) -> None:
    # A pinned dependency with known CVEs. govulncheck (Go) is optional, so a
    # Python manifest exercises trivy and grype without failing on the missing module.
    (repo / "requirements.txt").write_text("Django==2.2.0\n")


def verify(artifact: sarif.SarifDocument) -> None:
    # Django 2.2.0 (EOL since 2020) has many known CVEs. trivy and grype report them
    # as SARIF results with CVE-format rule IDs; the result messages and/or rule
    # descriptions reference the vulnerable package by name.
    results = artifact.results()
    assert results, "expected at least one vulnerability finding"
    rule_ids = {r.rule_id for r in results}
    cves = {rid for rid in rule_ids if rid.startswith("CVE-")}
    assert cves, f"expected CVE rule IDs, got {sorted(rule_ids)}"
    # Verify the findings are for the planted package (Django), not noise: trivy and
    # grype carry the package name in the result message and/or the rule description.
    text = " ".join(r.message for r in results)
    for run in artifact.to_dict().get("runs", []):
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            text += " " + str(rule.get("shortDescription", {}).get("text", ""))
            text += " " + str(rule.get("fullDescription", {}).get("text", ""))
    assert "django" in text.lower(), (
        f"expected a Django finding among {len(cves)} CVEs; "
        f"rule IDs: {sorted(rule_ids)}"
    )

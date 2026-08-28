# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""SBOM scan fixture: a manifest so the bill of materials lists components."""

from pathlib import Path

from reposcan.scans import cyclonedx
from reposcan.scans.sbom import SbomScan

SCAN = SbomScan()


def plant(repo: Path) -> None:
    (repo / "requirements.txt").write_text("requests==2.31.0\nflask==3.0.0\n")


def verify(artifact: cyclonedx.CycloneDxDocument) -> None:
    # The SBOM lists the pinned direct dependencies from requirements.txt as
    # components. The temp dir is not a git repo, so resolve_dependencies leaves
    # it unchanged (no lockfile) and the tools read requirements.txt directly --
    # the two pinned packages appear with their exact versions.
    by_name = {str(c.get("name", "")): c for c in artifact.components()}
    for name, version in (("requests", "2.31.0"), ("flask", "3.0.0")):
        assert name in by_name, f"expected {name} in components, got {sorted(by_name)}"
        actual = by_name[name].get("version", "")
        assert actual == version, f"expected {name}=={version}, got {name}=={actual}"

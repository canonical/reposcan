# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Scan-fixture tests: run each scan against its fixture and enforce coverage.

Fixtures live one-per-scan under tests/scans/fixtures/, each exposing SCAN, plant,
and verify as data. This file loads them, runs each scan against its planted content
in the built tool image, and checks that every scan has a fixture and is wired to a
command. The real-tool test fails when docker is unavailable.
"""

import importlib
import importlib.util
import logging
import pkgutil
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Protocol, cast, runtime_checkable

import repo_scanner.scans as scans_pkg
from repo_scanner.backends import DockerBackend, start_session
from repo_scanner.execution.context import host_user
from repo_scanner.execution.process import Failure
from repo_scanner.scans import sarif
from repo_scanner.scans.base import Scan
from repo_scanner.scans.model import Artifact, ArtifactKind
from repo_scanner.scans.registry import SCANS
from repo_scanner.scans.run import run_scan
from repo_scanner.scans.sbom import SbomScan

logger = logging.getLogger(__name__)

_FIXTURES_DIR = Path(__file__).parent / "fixtures"


@runtime_checkable
class TestFixture(Protocol):
    """The contract every fixture file under fixtures/ provides."""

    SCAN: Scan
    plant: Callable[[Path], None]
    verify: Callable[[Artifact], None]


def _load_fixtures() -> dict[str, TestFixture]:
    """Load each fixture file under fixtures/, keyed by its scan's name."""
    fixtures: dict[str, TestFixture] = {}
    for path in sorted(_FIXTURES_DIR.glob("*.py")):
        spec = importlib.util.spec_from_file_location(
            f"_scan_fixture_{path.stem}", path
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        fixture = cast(TestFixture, module)
        fixtures[fixture.SCAN.name] = fixture
    return fixtures


def _discover_scans() -> dict[str, type[Scan]]:
    """Every concrete Scan defined under src/repo_scanner/scans, keyed by name."""
    scans: dict[str, type[Scan]] = {}
    for info in pkgutil.iter_modules(scans_pkg.__path__):
        module = importlib.import_module(f"{scans_pkg.__name__}.{info.name}")
        for obj in vars(module).values():
            # A concrete scan defined in this module (not imported, not a base): a
            # Scan subclass that sets its own `name` (the bases do not).
            defined_here = isinstance(obj, type) and obj.__module__ == module.__name__
            if defined_here and issubclass(obj, Scan) and hasattr(obj, "name"):
                scans[obj.name] = obj
    return scans


def test_every_scan_has_a_fixture_and_is_wired_to_a_command() -> None:
    discovered = _discover_scans()
    assert discovered, "no scans were discovered under src/repo_scanner/scans"
    fixtures = set(_load_fixtures())
    missing = set(discovered) - fixtures
    assert not missing, f"scans with no fixture: {sorted(missing)}"
    orphan = fixtures - set(discovered)
    assert not orphan, f"fixtures for unknown scans: {sorted(orphan)}"
    # Each scan is wired to a command, by artifact kind: the findings scans to `scan`
    # (the SCANS registry), the SBOM inventory to its own `sbom` command.
    findings = {
        n for n, c in discovered.items() if c.artifact_kind is ArtifactKind.SARIF
    }
    inventory = {
        n for n, c in discovered.items() if c.artifact_kind is ArtifactKind.CYCLONEDX
    }
    assert findings == set(SCANS)
    assert inventory == {SbomScan.name}


def _run_fixture(name: str, fixture: TestFixture) -> None:
    with tempfile.TemporaryDirectory() as directory:
        repo = Path(directory)
        fixture.plant(repo)
        logger.info("[docker] scanning the %s fixture", name)
        with start_session(
            "docker",
            tool_image=True,
            mount_source=str(repo),
            user=host_user(),
            image="build",
        ) as session:
            assert session.ok, f"session failed for {name} (exit {session.exit_code})"
            assert session.target is not None
            artifact = run_scan(
                fixture.SCAN,
                session.context,
                session.target,
                session.tool_root,
                stream=True,
            )
            assert not isinstance(artifact, Failure), f"{name}: {artifact}"
            fixture.verify(artifact)
            _assert_normalized_sarif(name, artifact)


def _assert_normalized_sarif(name: str, artifact: Artifact) -> None:
    """Enforce SARIF normalization.

    A scan should always produce a single run with the "reposcan" driver, and every
    result should include properties.scanners. A non-SARIF artifact is left alone.
    """
    if not isinstance(artifact, sarif.SarifDocument):
        return
    runs = artifact.to_dict()["runs"]
    assert len(runs) == 1, f"{name}: expected one run, got {len(runs)}"
    assert runs[0]["tool"]["driver"]["name"] == "reposcan", (
        f"{name}: driver not reposcan"
    )
    for result in artifact.results():
        assert result.scanners, f"{name}: result {result.rule_id!r} names no scanners"


def test_docker_fixtures_report_findings() -> None:
    availability = DockerBackend().availability()
    assert availability.ok, f"docker unavailable: {availability.reason}"
    for name, fixture in sorted(_load_fixtures().items()):
        _run_fixture(name, fixture)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)
    if len(sys.argv) <= 1:
        test_docker_fixtures_report_findings()
    else:
        target = sys.argv[1]
        fixture = _load_fixtures().get(target)
        if fixture is not None:
            _run_fixture(target, fixture)
            logger.info("%s passed", target)
        else:
            logger.error("No fixture found for %s!", target)

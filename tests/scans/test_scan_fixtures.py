# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Security-scan fixture tests.

Each SARIF scan (secrets/sast/iac/workflow/sca) has a fixture at fixtures/<name>.py
exposing SCAN, plant, and verify. The docker test runs each registered scan against its
planted content in the built tool image; the coverage test checks every scan reposcan
defines has a fixture and is wired to a command. The docker test fails (never skips)
when docker is unavailable. (The SBOM is covered separately, in test_sbom_fixtures.)
"""

import logging
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Protocol, cast

from repo_scanner.execution.process import Failure
from repo_scanner.scans import sarif
from repo_scanner.scans.base import SecurityScan
from repo_scanner.scans.registry import SCANS
from repo_scanner.scans.run import run_scan
from repo_scanner.scans.sbom import SbomScan
from tests.scans.shared import (
    discover_scans,
    fixture_names,
    load_fixture,
    planted_session,
    require_docker,
)

logger = logging.getLogger(__name__)


class SecurityFixture(Protocol):
    """The contract each SARIF-scan fixture provides."""

    SCAN: SecurityScan
    plant: Callable[[Path], None]
    verify: Callable[[sarif.SarifDocument], None]


def test_every_scan_has_a_fixture_and_is_wired_to_a_command() -> None:
    discovered = discover_scans()
    assert discovered, "no scans discovered under src/repo_scanner/scans"
    assert fixture_names() == set(discovered), "fixtures and scans are not one-to-one"
    security = {n for n, c in discovered.items() if issubclass(c, SecurityScan)}
    assert security == set(SCANS)  # the SARIF scans are exactly the SCANS registry
    assert set(discovered) - security == {
        SbomScan.name
    }  # the SBOM is the lone inventory


def _run(name: str) -> None:
    fixture = cast(SecurityFixture, load_fixture(name))
    with planted_session(name, fixture.plant) as session:
        assert session.target is not None
        run = run_scan(
            fixture.SCAN,
            session.context,
            session.target,
            session.tool_root,
            stream=True,
        )
        assert not isinstance(run, Failure), f"{name}: {run}"
        document = sarif.SarifDocument.from_runs([run])
        _assert_normalized(name, document)
        fixture.verify(document)


def _assert_normalized(name: str, document: sarif.SarifDocument) -> None:
    # A security scan always yields one run with the "reposcan" driver, every result
    # carrying its properties.scanners annotation.
    runs = document.to_dict()["runs"]
    assert len(runs) == 1, f"{name}: expected one run, got {len(runs)}"
    driver = runs[0]["tool"]["driver"]["name"]
    assert driver == "reposcan", f"{name}: driver not reposcan ({driver})"
    for result in document.results():
        assert result.scanners, f"{name}: result {result.rule_id!r} names no scanners"


def test_security_fixtures_report_findings() -> None:
    require_docker()
    for name in sorted(SCANS):
        _run(name)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)
    for target in sys.argv[1:] or sorted(SCANS):
        _run(target)
        logger.info("%s passed", target)

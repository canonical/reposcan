# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""SBOM fixture test.

fixtures/sbom.py exposes SCAN, plant, and verify. This runs the SBOM against its
planted content in the built tool image and checks the CycloneDX inventory. It fails
(never skips) when docker is unavailable. Fixture coverage (that the SBOM has a
fixture and is the lone inventory scan) is checked in test_scan_fixtures.
"""

import logging
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Protocol, cast

from repo_scanner.execution.process import Failure
from repo_scanner.scans import cyclonedx
from repo_scanner.scans.run import run_sbom_scan
from repo_scanner.scans.sbom import SbomScan
from tests.scans.shared import load_fixture, planted_session, require_docker

logger = logging.getLogger(__name__)


class SbomFixture(Protocol):
    """The contract the SBOM fixture provides."""

    SCAN: SbomScan
    plant: Callable[[Path], None]
    verify: Callable[[cyclonedx.CycloneDxDocument], None]


def _run() -> None:
    fixture = cast(SbomFixture, load_fixture(SbomScan.name))
    with planted_session(SbomScan.name, fixture.plant) as session:
        assert session.target is not None
        sbom = run_sbom_scan(
            fixture.SCAN,
            session.context,
            session.target,
            session.tool_root,
            stream=True,
        )
        assert not isinstance(sbom, Failure), f"sbom: {sbom}"
        fixture.verify(sbom)


def test_sbom_fixture_lists_components() -> None:
    require_docker()
    _run()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)
    _run()
    logger.info("sbom passed")

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Shared test fixtures and helpers."""

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, cast

import reposcan.scans.run as scans_run
from reposcan.execution.context import ExecutionContext
from reposcan.execution.process import Failure
from reposcan.scans import cyclonedx, sarif
from reposcan.scans.base import SecurityScan
from reposcan.scans.repo import ProjectIdentity, RepositoryState
from reposcan.scans.sbom import SbomScan

FAKE_REPOSITORY = RepositoryState(
    identity=ProjectIdentity(
        "acme", root_commit="c0ffee", origin="github.com/acme/acme"
    ),
    commit_sha="abc123",
    branch="main",
)


def build_sarif_run(num_results: int) -> sarif.SarifRun:
    """A SARIF run of `num_results` identical trufflehog results (run_scan's output)."""
    results = [
        sarif.SarifResult.build("AWS", "secret", "f.py", 1, "trufflehog", "/scan/x")
        for _ in range(num_results)
    ]
    return sarif.SarifRun.from_results("trufflehog", "3.95.8", results)


def build_sbom_artifact(components: int) -> cyclonedx.CycloneDxDocument:
    """A CycloneDX artifact listing `components` named components."""
    listed = [{"name": f"c{i}"} for i in range(components)]
    return cyclonedx.CycloneDxDocument({"bomFormat": "CycloneDX", "components": listed})


class FakeSession:
    """A started session over a placeholder context (run_scan is patched away)."""

    ok = True
    exit_code = 0
    context = cast(ExecutionContext, None)
    target = "/scan/x"
    install_dir = "/opt/reposcan"
    resolution_workdir = ""

    def __enter__(self) -> "FakeSession":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


@contextmanager
def patch_run_scan(
    module: Any,
    *outcomes: sarif.SarifRun | Failure,
    captured: list[SecurityScan] | None = None,
) -> Iterator[None]:
    """Patch `run_scan` to return `outcomes` in turn, one per scan the command runs.

    The command drives scans through `run_analysis`, so `run_scan` and
    `read_repository_state` are patched where that lives (`reposcan.scans.run`) while
    `start_session` is patched on the command `module`. Each call's scan is recorded
    into `captured` when given.
    """
    remaining: list[sarif.SarifRun | Failure] = list(outcomes)

    def fake(
        scan: SecurityScan, *args: object, **kwargs: object
    ) -> sarif.SarifRun | Failure:
        if captured is not None:
            captured.append(scan)
        return remaining.pop(0)

    saved_run = scans_run.run_scan
    saved_session = module.start_session
    saved_repository = scans_run.read_repository_state
    scans_run.run_scan = fake
    module.start_session = lambda *a, **k: FakeSession()
    scans_run.read_repository_state = lambda *a, **k: FAKE_REPOSITORY
    try:
        yield
    finally:
        scans_run.run_scan = saved_run
        module.start_session = saved_session
        scans_run.read_repository_state = saved_repository


@contextmanager
def patch_run_sbom_scan(
    module: Any,
    *outcomes: cyclonedx.CycloneDxDocument | Failure,
    captured: list[SbomScan] | None = None,
) -> Iterator[None]:
    """Patch the sbom command `module`'s `run_sbom_scan` to return `outcomes` in turn.

    Also patches `start_session` to a fake session and `read_repository_state` to
    `FAKE_REPOSITORY`; each call's scan is recorded into `captured` when given.
    """
    remaining: list[cyclonedx.CycloneDxDocument | Failure] = list(outcomes)

    def fake(
        scan: SbomScan, *args: object, **kwargs: object
    ) -> cyclonedx.CycloneDxDocument | Failure:
        if captured is not None:
            captured.append(scan)
        return remaining.pop(0)

    saved_gen = module.run_sbom_scan
    saved_session = module.start_session
    saved_repository = module.read_repository_state
    module.run_sbom_scan = fake
    module.start_session = lambda *a, **k: FakeSession()
    module.read_repository_state = lambda *a, **k: FAKE_REPOSITORY
    try:
        yield
    finally:
        module.run_sbom_scan = saved_gen
        module.start_session = saved_session
        module.read_repository_state = saved_repository

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Shared test fixtures and helpers."""

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, cast

from repo_scanner.execution.context import ExecutionContext
from repo_scanner.execution.process import Failure
from repo_scanner.scans import cyclonedx, sarif
from repo_scanner.scans.model import Artifact


def sarif_artifact(findings: int) -> Artifact:
    """A SARIF artifact with `findings` identical trufflehog results."""
    results = [
        sarif.SarifResult.build("AWS", "secret", "f.py", 1, "trufflehog", "/scan/x")
        for _ in range(findings)
    ]
    return sarif.SarifDocument.from_results("trufflehog", "3.95.8", results)


def sbom_artifact(components: int) -> Artifact:
    """A CycloneDX artifact listing `components` named components."""
    listed = [{"name": f"c{i}"} for i in range(components)]
    return cyclonedx.CycloneDxDocument({"bomFormat": "CycloneDX", "components": listed})


class FakeSession:
    """A started session over a placeholder context (run_scan is patched away)."""

    ok = True
    exit_code = 0
    context = cast(ExecutionContext, None)
    target = "/scan/x"
    tool_root = "/opt/reposcan"
    resolved_parent = ""

    def __enter__(self) -> "FakeSession":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


@contextmanager
def patch_scan(
    module: Any,
    *outcomes: Artifact | Failure,
    captured: list[Any] | None = None,
) -> Iterator[None]:
    """Patch `module.run_scan` to return `outcomes` in turn and `start_session` to a
    fake session. `module` is a command module (actions.scan or actions.sbom); each
    run_scan's scan argument is recorded into `captured` when given.
    """
    remaining = list(outcomes)
    saved_run, saved_session = module.run_scan, module.start_session

    def fake_run_scan(
        scan: object, *args: object, **kwargs: object
    ) -> Artifact | Failure:
        if captured is not None:
            captured.append(scan)
        return remaining.pop(0)

    module.run_scan = fake_run_scan
    module.start_session = lambda *args, **kwargs: FakeSession()
    try:
        yield
    finally:
        module.run_scan, module.start_session = saved_run, saved_session

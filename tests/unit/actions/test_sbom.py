# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the sbom command."""

import io
import tempfile
from contextlib import redirect_stdout

import repo_scanner.actions.sbom as sbom_cmd
from repo_scanner.execution.process import Failure
from repo_scanner.scans.sbom import SbomScan
from tests.unit.actions.helpers import patch_generate_sbom, sbom_artifact


def test_sbom_exits_zero_and_prints_a_component_table() -> None:
    out = io.StringIO()
    with tempfile.TemporaryDirectory() as repo:
        action = sbom_cmd.SbomCommand(path=repo)
        with patch_generate_sbom(sbom_cmd, sbom_artifact(3)), redirect_stdout(out):
            code = action.run()
    assert code == 0  # an SBOM is an inventory, never pass/fail
    assert "COMPONENT" in out.getvalue() and "c0" in out.getvalue()


def test_sbom_forwards_dependency_options_to_the_scan() -> None:
    captured: list[SbomScan] = []
    with tempfile.TemporaryDirectory() as repo:
        action = sbom_cmd.SbomCommand(
            path=repo, include_dev_dependencies=True, allow_code_execution=True
        )
        with (
            patch_generate_sbom(sbom_cmd, sbom_artifact(0), captured=captured),
            redirect_stdout(io.StringIO()),
        ):
            action.run()
    (scan,) = captured
    assert scan.include_dev_dependencies and scan.allow_code_execution


def test_sbom_reports_a_scan_failure_as_one() -> None:
    with tempfile.TemporaryDirectory() as repo:
        action = sbom_cmd.SbomCommand(path=repo)
        with patch_generate_sbom(sbom_cmd, Failure(reason="cdxgen crashed")):
            code = action.run()
    assert code == 1

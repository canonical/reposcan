# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base class(es) for scans."""

from typing import Any, ClassVar

from repo_scanner.cli_kit import flag, params_of
from repo_scanner.execution.context import ExecutionContext
from repo_scanner.execution.process import ExecResult, Failure
from repo_scanner.scans import sarif
from repo_scanner.scans.model import ToolInvocation


class Scan:
    """Base scan class.

    A concrete scan subclasses this, sets `name`/`help`, declares scan-specific options
    as typed class attributes, and implements `invocations`.
    """

    name: ClassVar[str]
    help: ClassVar[str]
    resolves_dependencies: ClassVar[bool] = False

    def __init__(self, **values: Any) -> None:
        params = params_of(type(self))
        unknown = set(values) - {param.name for param in params}
        if unknown:
            raise TypeError(f"unexpected arguments: {', '.join(sorted(unknown))}")
        for param in params:
            setattr(self, param.name, values.get(param.name, param.default))

    def invocations(self, ctx: ExecutionContext, target: str) -> list[ToolInvocation]:
        """The tool invocations to run against `target`, in run order.

        `ctx` is the started execution context, so a scan whose commands depend on the
        target's state can check it.
        """
        raise NotImplementedError


class SecurityScan(Scan):
    """Base class for security scans."""

    def create_run(
        self, tool: str, output: ExecResult, target: str
    ) -> sarif.SarifRun | Failure:
        """Turn a tool invocation's output into a SARIF run.

        Called once per executed tool; a tool invocation produces exactly one run.
        `tool` is the scanner that produced `output`; `target` is the scan root, used to
        make finding uris repository-root-relative.
        """
        raise NotImplementedError

    def add_fingerprints(
        self, run: sarif.SarifRun, ctx: ExecutionContext, target: str
    ) -> None:
        """Add SARIF fingerprints to `run`.

        Override the method for scans that require a different fingerprint.
        """
        sarif.add_primarylocationlinehash(run, ctx, target)


class DependencyResolvingScan(Scan):
    """A scan that resolves the dependency tree before scanning (sbom, sca).

    Mixed into `ScaScan` (also a `SecurityScan`) and the base of `SbomScan`, so both
    share the resolve options without duplicating them.
    """

    resolves_dependencies: ClassVar[bool] = True

    include_dev_dependencies: bool = flag(
        help="For sca/sbom: resolve development dependencies."
    )
    allow_code_execution: bool = flag(
        help="For sca/sbom: let resolution build source packages (off by default)"
    )

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base class(es) for Scans."""

from collections.abc import Sequence
from typing import Any, ClassVar

from repo_scanner.cli_kit import flag, params_of
from repo_scanner.execution.process import ExecResult, Failure
from repo_scanner.scans import cyclonedx, sarif
from repo_scanner.scans.model import Artifact, ArtifactKind, ToolInvocation


class Scan:
    """Base class for scans.

    A concrete scan subclasses this, sets `name`/`help`, declares scan-specific
    options as typed class attributes, and implements `invocations`/`parse`.
    """

    name: ClassVar[str]
    help: ClassVar[str]
    resolves_dependencies: ClassVar[bool] = False
    artifact_kind: ClassVar[ArtifactKind] = ArtifactKind.SARIF

    def __init__(self, **values: Any) -> None:
        params = params_of(type(self))
        unknown = set(values) - {param.name for param in params}
        if unknown:
            raise TypeError(f"unexpected arguments: {', '.join(sorted(unknown))}")
        for param in params:
            setattr(self, param.name, values.get(param.name, param.default))

    def invocations(self, target: str) -> list[ToolInvocation]:
        """The tool invocations to run against `target`, in run order."""
        raise NotImplementedError

    def parse(self, tool: str, output: ExecResult, target: str) -> Artifact | Failure:
        """Parse and normalize a tool invocation's raw output into an Artifact.

        Called once per executed tool. `tool` is the scanner that produced `output`;
        `target` is the scan root, used to make finding uris repository-root-relative.
        """
        raise NotImplementedError

    def consolidate(self, artifacts: Sequence[Artifact]) -> Artifact | Failure:
        """Merge this scan's per-tool Artifacts into one, by its artifact kind."""
        if self.artifact_kind is ArtifactKind.CYCLONEDX:
            return cyclonedx.merge(artifacts)
        return sarif.merge(artifacts)


class DependencyResolvingScan(Scan):
    """Base for scans that resolve the dependency tree before scanning (sbom, sca)."""

    resolves_dependencies: ClassVar[bool] = True

    include_dev_dependencies: bool = flag(
        help="For sca: resolve development dependencies."
    )
    allow_code_execution: bool = flag(
        help="For sca: let dependency resolution build source packages (off by default)"
    )

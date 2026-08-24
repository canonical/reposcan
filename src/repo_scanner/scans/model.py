# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The scan data model/types."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, ClassVar, Protocol

from repo_scanner.ioutil.sqlitedb import Table


@dataclass(frozen=True)
class ToolInvocation:
    """A tool invocation: the tool, its args, and how to run/judge it.

    Some tools exit non-zero to signal findings rather than an error (e.g.
    govulncheck exits 3); `ok_codes` lists the exit codes that mean success, so
    run_scan does not mistake findings for a failure. `cwd` overrides the working
    directory the tool runs in; when None it defaults to the target repo.
    `env` adds environment variables for the run. `output_file` names a file the tool
    writes its result to, for tools whose stdout is unreliable: run_scan reads that
    file and uses its content as the tool's output instead of the tool's stdout.
    `optional` marks a tool that may not apply to every repo (e.g. govulncheck on a
    non-Go repo): its failure is logged and skipped rather than failing the whole scan.
    """

    tool: str
    args: list[str]
    ok_codes: tuple[int, ...] = (0,)
    cwd: str | None = None
    env: Mapping[str, str] | None = None
    output_file: str | None = None
    optional: bool = False


@dataclass(frozen=True)
class ToolInvocationRecord(ToolInvocation):
    """Provenance for one executed tool command, recorded in a report's metadata.

    `command` is the full argv as run (executable and every argument). `environment`
    holds only the variables reposcan set for the run, never the inherited process
    environment, so no ambient secrets are written into a shareable report.
    """

    version: str = ""
    command: tuple[str, ...] = ()
    working_directory: str = ""
    environment: Mapping[str, str] = field(default_factory=dict)
    exit_code: int = -1
    successful: bool = False


class ArtifactKind(str, Enum):
    """Scan artifact types."""

    SARIF = "sarif"
    CYCLONEDX = "cyclonedx"


class Artifact(Protocol):
    """A consolidated scan result: a JSON-serialisable document of a known kind."""

    kind: ClassVar[ArtifactKind]

    def to_dict(self) -> dict[str, Any]:
        """The artifact rendered as a dictionary for JSON serialization."""
        ...

    def count(self) -> int:
        """The number of entries the artifact holds (findings, or components)."""
        ...

    def rows(self) -> tuple[list[str], list[list[str]]]:
        """A table view of the artifact: column headers and one row per entry."""
        ...

    def records(self) -> Table:
        """The artifact as a db table: schema plus one row per entry."""
        ...

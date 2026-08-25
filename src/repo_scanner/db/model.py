# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The records handed to the report database, and the summaries read back out."""

from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum

from repo_scanner.scans import cyclonedx, sarif
from repo_scanner.scans.model import ArtifactKind, ToolInvocationRecord
from repo_scanner.scans.repo import RepositoryState


class RunStatus(str, Enum):
    """Status of a completed, partially-complete, or failed run."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass(frozen=True)
class ScanRecord:
    """The record of one `reposcan scan` or `reposcan sbom` invocation."""

    uuid: str
    started_at: str
    finished_at: str
    reposcan_version: str
    repository: RepositoryState
    produced_by: str = ""
    status: RunStatus = RunStatus.COMPLETE


@dataclass(frozen=True)
class RunRecord:
    """Record of one scan run, including its results and provenance.

    `produced` is a single SARIF run, or the whole CycloneDX document for an SBOM.
    """

    category: str
    kind: ArtifactKind
    started_at: str
    finished_at: str
    status: RunStatus
    produced: "sarif.SarifRun | cyclonedx.CycloneDxDocument"
    invocations: Sequence[ToolInvocationRecord] = ()


@dataclass(frozen=True)
class ProjectSummary:
    """Project identifier."""

    project_id: int
    name: str
    root_commit: str = ""
    origin: str = ""
    label: str = ""


@dataclass(frozen=True)
class ScanSummary:
    """Summary of a scan."""

    scan_id: int
    project_id: int
    uuid: str
    started_at: str
    status: RunStatus
    produced_by: str = ""
    commit_sha: str = ""
    branch: str = ""
    dirty: bool = False
    shallow: bool = False
    categories: tuple[str, ...] = ()

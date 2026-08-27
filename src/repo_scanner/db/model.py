# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Intermediate Python objects for working with the databasel."""

from dataclasses import dataclass
from enum import Enum

from repo_scanner.scans import cyclonedx, sarif
from repo_scanner.scans.model import ArtifactKind
from repo_scanner.scans.repo import RepositoryState


class ScanStatus(str, Enum):
    """Status of a completed, partially-complete, or failed scan."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass(frozen=True)
class AnalysisRecord:
    """The record of one `reposcan scan` or `reposcan sbom` invocation."""

    uuid: str
    started_at: str
    finished_at: str
    reposcan_version: str
    repository: RepositoryState
    produced_by: str = ""
    status: ScanStatus = ScanStatus.COMPLETE


@dataclass(frozen=True)
class ScanRecord:
    """Record of one scan type's execution.

    `produced` is a single SARIF run, or the whole CycloneDX document for an SBOM.
    """

    category: str
    kind: ArtifactKind
    started_at: str
    finished_at: str
    status: ScanStatus
    produced: sarif.SarifRun | cyclonedx.CycloneDxDocument


@dataclass(frozen=True)
class Issue:
    """One issue and the span of analyses that have reported it."""

    issue_id: int
    project_id: int
    category: str
    rule: str
    first_seen_analysis: int
    last_seen_analysis: int


@dataclass(frozen=True)
class Component:
    """One component and the span of analyses that have reported it."""

    component_id: int
    project_id: int
    component_key: str
    first_seen_analysis: int
    last_seen_analysis: int


@dataclass(frozen=True)
class ComponentVersion:
    """One version of a component."""

    version: str
    first_seen_analysis: int
    last_seen_analysis: int
    analysis_count: int


@dataclass(frozen=True)
class ProjectSummary:
    """Project identifier."""

    project_id: int
    name: str
    root_commit: str = ""
    origin: str = ""
    label: str = ""


@dataclass(frozen=True)
class AnalysisSummary:
    """Summary of an analysis."""

    analysis_id: int
    project_id: int
    uuid: str
    started_at: str
    status: ScanStatus
    produced_by: str = ""
    commit_sha: str = ""
    branch: str = ""
    dirty: bool = False
    shallow: bool = False
    categories: tuple[str, ...] = ()

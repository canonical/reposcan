# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Data model and utilities for a reposcan 'analysis': one session or set of scans.

Separate from model.py due to import order/layering. sarif/cyclonedx import model.py and
use its data models, while analysis imports and uses the sarif/cyclonedx data models.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from reposcan import reposcan_version
from reposcan.scans import cyclonedx, sarif
from reposcan.scans.model import ArtifactKind
from reposcan.scans.repo import RepositoryState

ScanOutput = sarif.SarifRun | cyclonedx.CycloneDxDocument


def utc_now() -> str:
    """The current time in the ISO-8601 UTC format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ScanStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


def scan_status(produced: ScanOutput) -> ScanStatus:
    """Determine scan status (complete, partial, failed) based on invocation success."""
    if any(not invocation.successful for invocation in produced.tool_invocations):
        return ScanStatus.PARTIAL
    return ScanStatus.COMPLETE


@dataclass(frozen=True)
class ScanRecord:
    """Scan execution record."""

    category: str
    kind: ArtifactKind
    started_at: str
    finished_at: str
    status: ScanStatus
    produced: ScanOutput

    @classmethod
    def from_artifact(
        cls, category: str, produced: ScanOutput, *, started_at: str, finished_at: str
    ) -> "ScanRecord":
        """Create a ScanRecord from a SarifRun or CycloneDxDocument."""
        return cls(
            category=category,
            kind=produced.kind,
            started_at=started_at,
            finished_at=finished_at,
            status=scan_status(produced),
            produced=produced,
        )


@dataclass
class Analysis:
    """One reposcan session with one or more scans.

    The Analysis object is built as the scans run rather than assembled afterwards.
    `begin` sets the start timestamp and reads the repository metadata; `add` records
    the product of each new scan; `close` sets the end timestamp and writes the
    analysis metadata into each associated artifact.
    """

    uuid: str
    started_at: str
    reposcan_version: str
    repository: RepositoryState
    finished_at: str = ""
    produced_by: str = ""
    status: ScanStatus = ScanStatus.COMPLETE
    scans: list[ScanRecord] = field(default_factory=list)

    @classmethod
    def begin(cls, repository: RepositoryState) -> "Analysis":
        """Start an analysis of `repository`."""
        return cls(
            uuid=str(uuid4()),
            started_at=utc_now(),
            reposcan_version=reposcan_version(),
            repository=repository,
        )

    def add(self, category: str, produced: ScanOutput, *, started_at: str) -> None:
        """Add the record of a finalized scan to the analysis."""
        self.scans.append(
            ScanRecord.from_artifact(
                category, produced, started_at=started_at, finished_at=utc_now()
            )
        )

    def close(self) -> None:
        """Finalize the analysis."""
        self.finished_at = utc_now()
        for scan in self.scans:
            scan.produced.record_provenance(
                self.repository,
                analysis_uuid=self.uuid,
                started_at=self.started_at,
                finished_at=self.finished_at,
                reposcan_version=self.reposcan_version,
            )

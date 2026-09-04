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

from reposcan import __version__
from reposcan.scans import cyclonedx, sarif
from reposcan.scans.model import ArtifactKind
from reposcan.scans.repo import RepositoryState

ScanOutput = sarif.SarifRun | cyclonedx.CycloneDxDocument


def utc_now() -> str:
    """Report the current time in the ISO-8601 UTC format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ScanStatus(str, Enum):
    STARTED = "started"
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
        cls, category: str, produced: ScanOutput, *, started_at: str
    ) -> "ScanRecord":
        """Create a ScanRecord from a SarifRun or CycloneDxDocument."""
        return cls(
            category=category,
            kind=produced.kind,
            started_at=started_at,
            finished_at=utc_now(),
            status=scan_status(produced),
            produced=produced,
        )


@dataclass
class Analysis:
    """One reposcan session with one or more scans.

    The Analysis object is built as the scans run rather than assembled afterwards.
    `begin` sets the start timestamp and reads the repository metadata; `add` takes
    each finished scan's record; `close` sets the end timestamp and writes the
    analysis metadata into each associated artifact.

    Use it as a context manager so `close` cannot be forgotten.
    """

    uuid: str
    started_at: str
    reposcan_version: str
    repository: RepositoryState
    finished_at: str = ""
    produced_by: str = ""
    status: ScanStatus = ScanStatus.STARTED
    successful_scans: list[ScanRecord] = field(default_factory=list)
    failed_scans: list[str] = field(default_factory=list)

    @classmethod
    def begin(cls, repository: RepositoryState) -> "Analysis":
        """Start an analysis of `repository`."""
        return cls(
            uuid=str(uuid4()),
            started_at=utc_now(),
            reposcan_version=__version__,
            repository=repository,
        )

    def __enter__(self) -> "Analysis":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        """Close the analysis on every exit, including an error path."""
        self.close()

    def add(self, record: ScanRecord) -> None:
        """Add a finished scan's record to the analysis."""
        self.successful_scans.append(record)

    def fail(self, category: str) -> None:
        """Record that `category`'s scan produced nothing."""
        self.failed_scans.append(category)

    @property
    def sarif_runs(self) -> list[sarif.SarifRun]:
        """Every SARIF run recorded here, in scan order.

        An analysis may hold CycloneDX output too, so products are filtered for SARIF.
        """
        return [
            record.produced
            for record in self.successful_scans
            if isinstance(record.produced, sarif.SarifRun)
        ]

    def close(self) -> None:
        """Finalize the analysis."""
        self.finished_at = utc_now()
        for scan in self.successful_scans:
            scan.produced.record_provenance(
                self.repository,
                analysis_uuid=self.uuid,
                started_at=self.started_at,
                finished_at=self.finished_at,
                reposcan_version=self.reposcan_version,
            )
        if not self.failed_scans:
            self.status = ScanStatus.COMPLETE
        elif not self.successful_scans:
            self.status = ScanStatus.FAILED
        else:
            self.status = ScanStatus.PARTIAL

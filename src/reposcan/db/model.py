# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Intermediate Python objects for working with the database."""

from dataclasses import dataclass

from reposcan.scans.analysis import ScanStatus


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

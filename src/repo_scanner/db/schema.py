# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Schema(s) for every table and statement.

The statements are literals, so no SQL is assembled from strings. Each CREATE includes
`IF NOT EXISTS` for idempotency.

`SCHEMA_VERSION` is used to check if the database was written by a different version of
reposcan.
"""

from pathlib import Path

from repo_scanner.db.sqlite import Session, TableSchema, read_version

SCHEMA_VERSION = 1

PROJECT = TableSchema(
    name="project",
    columns=(
        "name",  # the scanned directory's name
        "root_commit",  # the repository's first commit(s), sorted and comma-joined
        "origin",  # the remote url, normalized so ssh and https forms compare equal
        "label",  # an explicit assertion from the caller, which overrules the rest
    ),
    create="""
CREATE TABLE IF NOT EXISTS project (
    project_id   INTEGER PRIMARY KEY,
    name         TEXT NOT NULL,
    root_commit  TEXT NOT NULL DEFAULT '',
    origin       TEXT NOT NULL DEFAULT '',
    label        TEXT NOT NULL DEFAULT ''
)
""",
    insert="""
INSERT INTO project (name, root_commit, origin, label)
     VALUES (?, ?, ?, ?)
""",
    select="""
SELECT project_id, name, root_commit, origin, label
  FROM project
 ORDER BY project_id
""",
)

# One row per reposcan session/analysis, holding one scan per scan type.
ANALYSIS = TableSchema(
    name="analysis",
    columns=(
        "uuid",  # identifies the analysis across databases; re-importing is a no-op
        "produced_by",  # who ran it; empty == this machine
        "project_id",  # the repository it covered
        "started_at",  # ISO-8601 UTC, wall clock rather than anything git said
        "finished_at",  # ISO-8601 UTC, empty while it is still being recorded
        "reposcan_version",  # the version of reposcan that ran it
        "target_name",  # the scanned directory's name, as this analysis saw it
        "branch",  # the checked-out branch; empty when detached, a tag, or not git
        "commit_sha",  # the commit HEAD pointed at; empty when not a git repository
        "dirty",  # boolean flag: whether the working tree differed from commit_sha
        "shallow",  # boolean flag: whether the git history was truncated
        "status",  # complete, partial, or failed
    ),
    create="""
CREATE TABLE IF NOT EXISTS analysis (
    analysis_id       INTEGER PRIMARY KEY,
    uuid              TEXT NOT NULL UNIQUE,
    produced_by       TEXT NOT NULL DEFAULT '',
    project_id        INTEGER NOT NULL REFERENCES project(project_id),
    started_at        TEXT NOT NULL,
    finished_at       TEXT NOT NULL DEFAULT '',
    reposcan_version  TEXT NOT NULL,
    target_name       TEXT NOT NULL,
    branch            TEXT NOT NULL DEFAULT '',
    commit_sha        TEXT NOT NULL DEFAULT '',
    dirty             INTEGER NOT NULL DEFAULT 0,
    shallow           INTEGER NOT NULL DEFAULT 0,
    status            TEXT NOT NULL
)
""",
    insert="""
INSERT INTO analysis (uuid, produced_by, project_id, started_at, finished_at,
                      reposcan_version, target_name, branch, commit_sha, dirty,
                      shallow, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
""",
)

# One row per scan within an analysis. A scan is one scan type's execution, which may
# have taken more than one tool to carry out.
SCAN = TableSchema(
    name="scan",
    columns=(
        "analysis_id",  # the analysis this scan belongs to (foreign key)
        "category",  # the scan type (sast, secrets, sbom, ...), and the closure scope
        "artifact_kind",  # sarif or cyclonedx
        "started_at",  # ISO-8601 UTC
        "finished_at",  # ISO-8601 UTC
        "status",  # complete, partial, or failed
        "artifact_shell",  # the artifact with its entries and invocations emptied out
    ),
    create="""
CREATE TABLE IF NOT EXISTS scan (
    scan_id         INTEGER PRIMARY KEY,
    analysis_id     INTEGER NOT NULL REFERENCES analysis(analysis_id),
    category        TEXT NOT NULL,
    artifact_kind   TEXT NOT NULL,
    started_at      TEXT NOT NULL DEFAULT '',
    finished_at     TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL,
    artifact_shell  TEXT NOT NULL
)
""",
    insert="""
INSERT INTO scan (analysis_id, category, artifact_kind, started_at, finished_at,
                  status, artifact_shell)
     VALUES (?, ?, ?, ?, ?, ?, ?)
""",
)

# One row per tool command a scan executed, `command_index` giving the order they ran
# in. Lifted out of the artifact to make tool success queryable
INVOCATION = TableSchema(
    name="invocation",
    columns=(
        "scan_id",  # the scan that executed this command (foreign key)
        "command_index",  # the order the commands ran in, from zero
        "tool",  # the tool's registry name, such as "semgrep"
        "version",  # the pinned version that ran
        "command_json",  # the full argv as executed
        "working_directory",  # the directory it ran in, as seen in the context
        "environment_json",  # env vars set by reposcan for the command
        "exit_code",  # the code the process exited with
        "successful",  # whether that code counted as success for this tool
    ),
    create="""
CREATE TABLE IF NOT EXISTS invocation (
    scan_id            INTEGER NOT NULL REFERENCES scan(scan_id),
    command_index      INTEGER NOT NULL,
    tool               TEXT NOT NULL,
    version            TEXT NOT NULL,
    command_json       TEXT NOT NULL,
    working_directory  TEXT NOT NULL,
    environment_json   TEXT NOT NULL,
    exit_code          INTEGER NOT NULL,
    successful         INTEGER NOT NULL,
    PRIMARY KEY (scan_id, command_index)
)
""",
    insert="""
INSERT INTO invocation VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
""",
)

# The abstract issue that reports are matched onto. `rule` is here rather than on the
# report because two reports are never the same issue unless their rules agree, which
# makes it a property of the issue itself.
ISSUE = TableSchema(
    name="issue",
    columns=(
        "project_id",  # the repository it belongs to (foreign key)
        "category",  # the scan type that reported it, and the scope it is matched in
        "rule",  # the SARIF ruleId that fired, identical for every report
    ),
    create="""
CREATE TABLE IF NOT EXISTS issue (
    issue_id    INTEGER PRIMARY KEY,
    project_id  INTEGER NOT NULL REFERENCES project(project_id),
    category    TEXT NOT NULL,
    rule        TEXT NOT NULL
)
""",
    insert="""
INSERT INTO issue (project_id, category, rule)
     VALUES (?, ?, ?)
""",
)

# An abstract component. Unlike an issue, it is fully identified by a key derived from
# its package url, so the key is part of the component itself. It is scoped to the
# repository alone: whichever scan type reported a package, it is the same package.
COMPONENT = TableSchema(
    name="component",
    columns=(
        "project_id",  # the repository it belongs to (foreign key)
        "component_key",  # its derived identity; see db.identity
    ),
    create="""
CREATE TABLE IF NOT EXISTS component (
    component_id   INTEGER PRIMARY KEY,
    project_id     INTEGER NOT NULL REFERENCES project(project_id),
    component_key  TEXT NOT NULL,
    UNIQUE (project_id, component_key)
)
""",
    insert="""
INSERT INTO component (project_id, component_key)
     VALUES (?, ?)
""",
)

# One row per issue reported, per scan. A report is the output of a particular scan.
# `result_json` is the SARIF result itself, verbatim. The fingerprint columns are
# lifted out of it for queryability.
ISSUE_REPORT = TableSchema(
    name="issue_report",
    columns=(
        "scan_id",  # the scan that reported it (foreign key)
        "issue_id",  # the durable issue this is a report of (foreign key)
        "result_index",  # its place in the scan's `results`
        "level",  # error, warning, note, or none
        "uri",  # the file, relative to the repository root
        "line",  # the 1-indexed start line; empty when the report has no line
        "message",  # the human-readable description
        "scanners",  # every tool that reported it, comma-joined
        "fingerprints",  # complete fingerprints, as a JSON object
        "partial_fingerprints",  # partial fingerprints, as a JSON object
        "result_json",  # the SARIF result itself, verbatim
    ),
    create="""
CREATE TABLE IF NOT EXISTS issue_report (
    scan_id               INTEGER NOT NULL REFERENCES scan(scan_id),
    issue_id              INTEGER NOT NULL REFERENCES issue(issue_id),
    result_index          INTEGER NOT NULL,
    level                 TEXT NOT NULL DEFAULT '',
    uri                   TEXT NOT NULL DEFAULT '',
    line                  TEXT NOT NULL DEFAULT '',
    message               TEXT NOT NULL DEFAULT '',
    scanners              TEXT NOT NULL DEFAULT '',
    fingerprints          TEXT NOT NULL DEFAULT '{}',
    partial_fingerprints  TEXT NOT NULL DEFAULT '{}',
    result_json           TEXT NOT NULL,
    PRIMARY KEY (scan_id, result_index)
)
""",
    insert="""
INSERT INTO issue_report VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
""",
    select="""
SELECT result_json
  FROM issue_report
 WHERE scan_id = ?
 ORDER BY result_index
""",
)

# One row per component reported, per scan.
COMPONENT_REPORT = TableSchema(
    name="component_report",
    columns=(
        "scan_id",  # the scan that reported it (foreign key)
        "component_id",  # the durable component this is a report of (foreign key)
        "component_index",  # its place in the inventory the tool produced
        "name",  # the package name as the tool wrote it
        "version",  # the version this scan saw it pinned at
        "type",  # the CycloneDX classifier: library, application, and so on
        "purl",  # the package url, verbatim; identity normalizes it separately
        "scanners",  # every tool that reported it, comma-joined
        "component_json",  # the CycloneDX component itself, verbatim
    ),
    create="""
CREATE TABLE IF NOT EXISTS component_report (
    scan_id          INTEGER NOT NULL REFERENCES scan(scan_id),
    component_id     INTEGER NOT NULL REFERENCES component(component_id),
    component_index  INTEGER NOT NULL,
    name             TEXT NOT NULL DEFAULT '',
    version          TEXT NOT NULL DEFAULT '',
    type             TEXT NOT NULL DEFAULT '',
    purl             TEXT NOT NULL DEFAULT '',
    scanners         TEXT NOT NULL DEFAULT '',
    component_json   TEXT NOT NULL,
    PRIMARY KEY (scan_id, component_index)
)
""",
    insert="""
INSERT INTO component_report VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
""",
    select="""
SELECT component_json
  FROM component_report
 WHERE scan_id = ?
 ORDER BY component_index
""",
)

# Every fingerprint an issue has ever been reported with, for matching later reports.
ISSUE_FINGERPRINT = TableSchema(
    name="issue_fingerprint",
    columns=(
        "issue_id",  # the issue this was reported for (foreign key)
        "complete",  # 1 for a SARIF `fingerprints` entry, 0 for a partial one
        "name",  # the property name, versioned form included
        "value",  # its most recent value; a new value for a name replaces the old
    ),
    create="""
CREATE TABLE IF NOT EXISTS issue_fingerprint (
    issue_id  INTEGER NOT NULL REFERENCES issue(issue_id),
    complete  INTEGER NOT NULL,
    name      TEXT NOT NULL,
    value     TEXT NOT NULL,
    PRIMARY KEY (issue_id, complete, name)
) WITHOUT ROWID
""",
    insert="""
INSERT INTO issue_fingerprint VALUES (?, ?, ?, ?)
""",
)

TABLES = (
    PROJECT,
    ANALYSIS,
    SCAN,
    INVOCATION,
    ISSUE,
    COMPONENT,
    ISSUE_REPORT,
    COMPONENT_REPORT,
    ISSUE_FINGERPRINT,
)

# --- statements that are not a plain create, insert, or select-all ---

SELECT_PROJECTS = PROJECT.select
SELECT_ANALYSIS_BY_UUID = """
SELECT analysis_id
  FROM analysis
 WHERE uuid = ?
"""

SELECT_LATEST_ANALYSIS = """
SELECT analysis_id
  FROM analysis
 ORDER BY analysis_id DESC
 LIMIT 1
"""

SELECT_LATEST_ANALYSIS_FOR_PROJECT = """
SELECT analysis_id
  FROM analysis
 WHERE project_id = ?
 ORDER BY analysis_id DESC
 LIMIT 1
"""

SELECT_ANALYSES = """
SELECT analysis_id, project_id, uuid, started_at, status, produced_by,
       commit_sha, branch, dirty, shallow
  FROM analysis
 ORDER BY analysis_id
"""

SELECT_CATEGORIES_FOR_ANALYSIS = """
SELECT category
  FROM scan
 WHERE analysis_id = ?
 ORDER BY scan_id
"""

SELECT_SCANS_FOR_ANALYSIS = """
SELECT scan_id, category, artifact_kind, artifact_shell
  FROM scan
 WHERE analysis_id = ?
 ORDER BY scan_id
"""


# Every issue of one project, scan type, and rule, with its most recently reported uri
# and line, LEFT JOINed with the latest value for every fingerprint ever reported for
# said issue.
SELECT_CANDIDATES = """
SELECT i.issue_id, r.uri, r.line, p.complete, p.name, p.value
  FROM issue i
  JOIN issue_report r
    ON r.issue_id = i.issue_id
   AND r.scan_id = (SELECT MAX(scan_id)
                      FROM issue_report
                     WHERE issue_id = i.issue_id)
  LEFT JOIN issue_fingerprint p
    ON p.issue_id = i.issue_id
 WHERE i.project_id = ?
   AND i.category = ?
   AND i.rule = ?
 ORDER BY i.issue_id
"""
# Candidate lookup filters on all three, and rule is the selective one.
ISSUE_SCOPE_INDEX = """
CREATE INDEX IF NOT EXISTS issue_scope
    ON issue(project_id, category, rule)
"""

ISSUE_REPORT_INDEX = """
CREATE INDEX IF NOT EXISTS issue_report_issue
    ON issue_report(issue_id, scan_id)
"""

COMPONENT_REPORT_INDEX = """
CREATE INDEX IF NOT EXISTS component_report_component
    ON component_report(component_id)
"""

INDEXES = (ISSUE_SCOPE_INDEX, ISSUE_REPORT_INDEX, COMPONENT_REPORT_INDEX)
# Insert (or update) a fingerprint an issue was reported with.
UPSERT_ISSUE_FINGERPRINT = """
INSERT INTO issue_fingerprint (issue_id, complete, name, value)
     VALUES (?, ?, ?, ?)
         ON CONFLICT(issue_id, complete, name)
         DO UPDATE SET value = excluded.value
"""
# Every fingerprint of every issue of one project and scan type, for matching.
SELECT_ISSUE_FINGERPRINTS = """
SELECT f.issue_id, f.complete, f.name, f.value
  FROM issue_fingerprint f
  JOIN issue i
    ON i.issue_id = f.issue_id
 WHERE i.project_id = ?
   AND i.category = ?
"""
SELECT_COMPONENT_ID = """
SELECT component_id
  FROM component
 WHERE project_id = ?
   AND component_key = ?
"""
SELECT_ISSUES = """
SELECT i.issue_id, i.project_id, i.category, i.rule,
       s.first_seen_analysis, s.last_seen_analysis
  FROM issue i
  JOIN issue_span s
    ON s.issue_id = i.issue_id
 WHERE i.project_id = ?
 ORDER BY i.issue_id
"""
SELECT_COMPONENTS = """
SELECT c.component_id, c.project_id, c.component_key,
       s.first_seen_analysis, s.last_seen_analysis
  FROM component c
  JOIN component_span s
    ON s.component_id = c.component_id
 WHERE c.project_id = ?
 ORDER BY c.component_id
"""


def is_current(path: str) -> bool:
    """Whether `path` is a reposcan database of the version this reposcan reads."""
    return read_version(path) == SCHEMA_VERSION


def unusable(path: str) -> str | None:
    """Why `path` cannot be written to as a reposcan database, or None if it can.

    A path that does not exist, or an empty file a caller has reserved, is usable: it
    becomes a new database. Anything else has to already be a database of this
    version, because versions are checked rather than migrated.
    """
    version = read_version(path)
    if version is None:
        return f"{path} is not a sqlite database" if Path(path).exists() else None
    if version in (0, SCHEMA_VERSION):
        return None
    return (
        f"{path} is a version {version} reposcan database; "
        f"this reposcan writes version {SCHEMA_VERSION}"
    )


# When an issue was first and last reported
ISSUE_SPAN_VIEW = """
CREATE VIEW IF NOT EXISTS issue_span AS
    SELECT r.issue_id                AS issue_id,
           MIN(s.analysis_id)        AS first_seen_analysis,
           MAX(s.analysis_id)        AS last_seen_analysis
      FROM issue_report r
      JOIN scan s ON s.scan_id = r.scan_id
     GROUP BY r.issue_id
"""

# When a component was first and last reported
COMPONENT_SPAN_VIEW = """
CREATE VIEW IF NOT EXISTS component_span AS
    SELECT r.component_id            AS component_id,
           MIN(s.analysis_id)        AS first_seen_analysis,
           MAX(s.analysis_id)        AS last_seen_analysis
      FROM component_report r
      JOIN scan s ON s.scan_id = r.scan_id
     GROUP BY r.component_id
"""

COMPONENT_VERSION_VIEW = """
CREATE VIEW IF NOT EXISTS component_version AS
    SELECT r.component_id            AS component_id,
           r.version                 AS version,
           MIN(s.analysis_id)        AS first_seen_analysis,
           MAX(s.analysis_id)        AS last_seen_analysis,
           COUNT(DISTINCT s.analysis_id) AS analysis_count
      FROM component_report r
      JOIN scan s ON s.scan_id = r.scan_id
     WHERE r.version <> ''
     GROUP BY r.component_id, r.version
"""

VIEWS = (ISSUE_SPAN_VIEW, COMPONENT_SPAN_VIEW, COMPONENT_VERSION_VIEW)

SELECT_COMPONENT_VERSIONS = """
SELECT version, first_seen_analysis, last_seen_analysis, analysis_count
  FROM component_version
 WHERE component_id = ?
 ORDER BY first_seen_analysis, version
"""


def create_all(session: Session) -> None:
    """Create every table, index, and view if absent, and stamp the version."""
    for table in TABLES:
        session.create(table)
    for index in INDEXES:
        session.execute(index)
    for view in VIEWS:
        session.execute(view)
    session.set_version(SCHEMA_VERSION)

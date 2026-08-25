# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Schema(s) for every table and statement in the report database.

The statements are literals, so no SQL is assembled from strings. Each CREATE includes
`IF NOT EXISTS` for idempotency.

`SCHEMA_VERSION` is used to check if the database was written by a different version of
reposcan.
"""

from pathlib import Path

from repo_scanner.ioutil.sqlitedb import Session, TableSchema, read_version

SCHEMA_VERSION = 1

PROJECT = TableSchema(
    name="project",
    columns=(
        "name",  # the scanned directory's name
        "root_commit",  # the repository's first commit(s), sorted and comma-joined
        "origin",  # the remote url, normalized so ssh and https forms compare equal
        "label",  # an explicit assertion from the caller, which overrules the rest
    ),
    create=(
        "CREATE TABLE IF NOT EXISTS project ("
        "project_id INTEGER PRIMARY KEY, "
        "name TEXT NOT NULL, "
        "root_commit TEXT NOT NULL DEFAULT '', "
        "origin TEXT NOT NULL DEFAULT '', "
        "label TEXT NOT NULL DEFAULT '')"
    ),
    insert="INSERT INTO project (name, root_commit, origin, label) VALUES (?, ?, ?, ?)",
    select="SELECT project_id, name, root_commit, origin, label FROM project"
    " ORDER BY project_id",
)

SCAN = TableSchema(
    name="scan",
    columns=(
        "uuid",  # identifies the scan across databases; re-importing it is a no-op
        "produced_by",  # who ran the scan; empty means this machine did
        "project_id",  # the repository it covered
        "started_at",  # ISO-8601 UTC, wall clock rather than anything git said
        "finished_at",  # ISO-8601 UTC, empty while the scan is still being recorded
        "reposcan_version",  # the version of reposcan that ran the scan
        "target_name",  # the scanned directory's name, as this scan saw it
        "branch",  # the checked-out branch; empty when detached, a tag, or not git
        "commit_sha",  # the commit HEAD pointed at; empty when not a git repository
        "dirty",  # boolean flag: whether the working tree differed from commit_sha
        "shallow",  # boolean flag: whether the git history was truncated
        "status",  # complete, partial, or failed
    ),
    create=(
        "CREATE TABLE IF NOT EXISTS scan ("
        "scan_id INTEGER PRIMARY KEY, "
        "uuid TEXT NOT NULL UNIQUE, "
        "produced_by TEXT NOT NULL DEFAULT '', "
        "project_id INTEGER NOT NULL REFERENCES project(project_id), "
        "started_at TEXT NOT NULL, "
        "finished_at TEXT NOT NULL DEFAULT '', "
        "reposcan_version TEXT NOT NULL, "
        "target_name TEXT NOT NULL, "
        "branch TEXT NOT NULL DEFAULT '', "
        "commit_sha TEXT NOT NULL DEFAULT '', "
        "dirty INTEGER NOT NULL DEFAULT 0, "
        "shallow INTEGER NOT NULL DEFAULT 0, "
        "status TEXT NOT NULL)"
    ),
    insert=(
        "INSERT INTO scan (uuid, produced_by, project_id, started_at, finished_at, "
        "reposcan_version, target_name, branch, commit_sha, dirty, shallow, status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ),
    select=(
        "SELECT scan_id, uuid, produced_by, project_id, started_at, finished_at, "
        "target_name, branch, commit_sha, dirty, shallow, status "
        "FROM scan ORDER BY scan_id"
    ),
)

# One row per run within a scan.
RUN = TableSchema(
    name="run",
    columns=(
        "scan_id",  # the scan this run belongs to (forieng key)
        "category",  # the scan type (sast, secrets, sbom, ...), and the closure scope
        "artifact_kind",  # sarif or cyclonedx
        "started_at",  # ISO-8601 UTC
        "finished_at",  # ISO-8601 UTC
        "status",  # complete, partial, or failed
        "artifact_shell",  # the artifact with its entries and invocations emptied out
    ),
    create=(
        "CREATE TABLE IF NOT EXISTS run ("
        "run_id INTEGER PRIMARY KEY, "
        "scan_id INTEGER NOT NULL REFERENCES scan(scan_id), "
        "category TEXT NOT NULL, "
        "artifact_kind TEXT NOT NULL, "
        "started_at TEXT NOT NULL DEFAULT '', "
        "finished_at TEXT NOT NULL DEFAULT '', "
        "status TEXT NOT NULL, "
        "artifact_shell TEXT NOT NULL)"
    ),
    insert=(
        "INSERT INTO run (scan_id, category, artifact_kind, started_at, finished_at, "
        "status, artifact_shell) VALUES (?, ?, ?, ?, ?, ?, ?)"
    ),
    select=(
        "SELECT run_id, scan_id, category, artifact_kind, started_at, finished_at, "
        "status, artifact_shell FROM run ORDER BY run_id"
    ),
)

# One row per tool command a run executed, `command_index` giving the order they ran
# in. Lifted out of the artifact to make tool success queryable
INVOCATION = TableSchema(
    name="invocation",
    columns=(
        "run_id",  # the run that executed this command (foreign key)
        "command_index",  # the order the commands ran in, from zero
        "tool",  # the tool's registry name, such as "semgrep"
        "version",  # the pinned version that ran
        "command_json",  # the full argv as executed
        "working_directory",  # the directory it ran in, as seen in the context
        "environment_json",  # env vars set by reposcan for the command
        "exit_code",  # the code the process exited with
        "successful",  # whether that code counted as success for this tool
    ),
    create=(
        "CREATE TABLE IF NOT EXISTS invocation ("
        "run_id INTEGER NOT NULL REFERENCES run(run_id), "
        "command_index INTEGER NOT NULL, "
        "tool TEXT NOT NULL, "
        "version TEXT NOT NULL, "
        "command_json TEXT NOT NULL, "
        "working_directory TEXT NOT NULL, "
        "environment_json TEXT NOT NULL, "
        "exit_code INTEGER NOT NULL, "
        "successful INTEGER NOT NULL, "
        "PRIMARY KEY (run_id, command_index))"
    ),
    insert="INSERT INTO invocation VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    select=(
        "SELECT tool, version, command_json, working_directory, environment_json, "
        "exit_code, successful FROM invocation WHERE run_id = ? "
        "ORDER BY command_index"
    ),
)

# One row per finding, per run.
#
# `result_json` is the finding itself, verbatim. The fingerprint columns are lifted
# out of it for queryability.
FINDINGS = TableSchema(
    name="findings",
    columns=(
        "run_id",  # the run that reported this finding (foreign key)
        "result_index",  # its place in the run's `results`
        "rule",  # the SARIF ruleId that fired
        "level",  # error, warning, note, or none
        "uri",  # the file, relative to the repository root
        "line",  # the 1-indexed start line; empty when the finding has no line
        "message",  # the human-readable description
        "scanners",  # every tool that reported it, comma-joined
        "fingerprints",  # complete fingerprints, as a JSON object
        "partial_fingerprints",  # partial fingerprints, as a JSON object
        "result_json",  # the SARIF result itself, verbatim
    ),
    create=(
        "CREATE TABLE IF NOT EXISTS findings ("
        "run_id INTEGER NOT NULL REFERENCES run(run_id), "
        "result_index INTEGER NOT NULL, "
        "rule TEXT NOT NULL DEFAULT '', "
        "level TEXT NOT NULL DEFAULT '', "
        "uri TEXT NOT NULL DEFAULT '', "
        "line TEXT NOT NULL DEFAULT '', "
        "message TEXT NOT NULL DEFAULT '', "
        "scanners TEXT NOT NULL DEFAULT '', "
        "fingerprints TEXT NOT NULL DEFAULT '{}', "
        "partial_fingerprints TEXT NOT NULL DEFAULT '{}', "
        "result_json TEXT NOT NULL, "
        "PRIMARY KEY (run_id, result_index))"
    ),
    insert="INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    select=("SELECT result_json FROM findings WHERE run_id = ? ORDER BY result_index"),
)

# One row per component, per run. `component_index` stores a component's order
# in the original inventory to support exact document re-creation.
COMPONENTS = TableSchema(
    name="components",
    columns=(
        "run_id",  # the run that reported this component
        "component_index",  # its place in the inventory the tool produced
        "name",  # the package name as the tool wrote it
        "version",  # the version this scan saw it pinned at
        "type",  # the CycloneDX classifier: library, application, and so on
        "purl",  # the package url, verbatim; identity normalizes it separately
        "scanners",  # every tool that reported it, comma-joined
        "component_json",  # the CycloneDX component itself, verbatim
    ),
    create=(
        "CREATE TABLE IF NOT EXISTS components ("
        "run_id INTEGER NOT NULL REFERENCES run(run_id), "
        "component_index INTEGER NOT NULL, "
        "name TEXT NOT NULL DEFAULT '', "
        "version TEXT NOT NULL DEFAULT '', "
        "type TEXT NOT NULL DEFAULT '', "
        "purl TEXT NOT NULL DEFAULT '', "
        "scanners TEXT NOT NULL DEFAULT '', "
        "component_json TEXT NOT NULL, "
        "PRIMARY KEY (run_id, component_index))"
    ),
    insert="INSERT INTO components VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    select=(
        "SELECT component_json FROM components "
        "WHERE run_id = ? ORDER BY component_index"
    ),
)

TABLES = (PROJECT, SCAN, RUN, INVOCATION, FINDINGS, COMPONENTS)

# --- statements that are not a plain create, insert, or select-all ---

SELECT_PROJECTS = PROJECT.select
SELECT_SCAN_BY_UUID = "SELECT scan_id FROM scan WHERE uuid = ?"
SELECT_LATEST_SCAN = "SELECT scan_id FROM scan ORDER BY scan_id DESC LIMIT 1"
SELECT_LATEST_SCAN_FOR_PROJECT = (
    "SELECT scan_id FROM scan WHERE project_id = ? ORDER BY scan_id DESC LIMIT 1"
)
SELECT_SCANS = (
    "SELECT scan_id, project_id, uuid, started_at, status, produced_by, "
    "commit_sha, "
    "branch, dirty, shallow FROM scan ORDER BY scan_id"
)
SELECT_CATEGORIES_FOR_SCAN = (
    "SELECT category FROM run WHERE scan_id = ? ORDER BY run_id"
)
SELECT_RUNS_FOR_SCAN = (
    "SELECT run_id, category, artifact_kind, artifact_shell FROM run "
    "WHERE scan_id = ? ORDER BY run_id"
)


def is_current(path: str) -> bool:
    """Whether `path` is a report database of the version this reposcan reads."""
    return read_version(path) == SCHEMA_VERSION


def unusable(path: str) -> str | None:
    """Why `path` cannot be written to as a report database, or None if it can.

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


def create_all(session: Session) -> None:
    """Create every table if absent and stamp the schema version."""
    for table in TABLES:
        session.create(table)
    session.set_version(SCHEMA_VERSION)

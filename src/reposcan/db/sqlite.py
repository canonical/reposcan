# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Read and write tabular data as a sqlite database.

Callers serialize their own values, and every read and write happens within a
`Session`.
"""

import logging
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import TracebackType
from typing import Any

from reposcan.result import Err, Result

# How long to wait for a lock before giving up.
BUSY_TIMEOUT_SECONDS = 30.0

logger = logging.getLogger(__name__)

# The 16-byte header every sqlite 3 database file starts with.
_MAGIC = b"SQLite format 3\x00"

_TABLE_EXISTS = "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?"


@dataclass(frozen=True)
class TableSchema:
    """A table's name, columns, and literal SQL statements.

    The statements are literals rather than assembled from the column names, so no SQL
    is string-formatted; only row values are bound (as `?` parameters). `insert` must
    carry one placeholder per column.
    """

    name: str
    columns: tuple[str, ...]
    create: str
    insert: str
    select: str | None = None

    def __post_init__(self) -> None:
        if self.insert.count("?") != len(self.columns):
            raise ValueError(
                f"{self.name}: {self.insert.count('?')} placeholders "
                f"for {len(self.columns)} columns"
            )


@dataclass(frozen=True)
class Table:
    """A table's schema together with its rows."""

    schema: TableSchema
    rows: Sequence[tuple[object, ...]]


def is_sqlite(data: bytes) -> bool:
    """Whether `data` begins with the sqlite database file header."""
    return data[:16] == _MAGIC


class SessionMode(Enum):
    """What a session may do to its database."""

    READ = "r"
    READ_AND_WRITE = "rw"


def connect(path: str, mode: SessionMode) -> "Result[Session]":
    """Open a session on the database at `path`.

    A READ_AND_WRITE session creates the file when it is absent; a READ session
    refuses to. Returns an error rather than raising.

    sqlite serializes writers. Write-ahead logging lets readers work while a write is in
    flight. A READ_AND_WRITE session takes the write lock as it begins, so the busy
    timeout makes a second writer wait for it rather than fail.
    """
    try:
        # isolation_level=None turns off sqlite3's implicit transaction handling, so
        # the session's own BEGIN/COMMIT are the only transaction boundaries.
        if mode is SessionMode.READ:
            connection = sqlite3.connect(
                Path(path).resolve().as_uri() + "?mode=ro",
                uri=True,
                isolation_level=None,
                timeout=BUSY_TIMEOUT_SECONDS,
            )
        else:
            connection = sqlite3.connect(
                path, isolation_level=None, timeout=BUSY_TIMEOUT_SECONDS
            )
            (journal,) = connection.execute("PRAGMA journal_mode = WAL").fetchone()
            if str(journal).lower() != "wal":
                logger.debug("%s is journalled as %s, not wal", path, journal)
    except sqlite3.Error as exc:
        return Err(f"could not open {path}: {exc}")
    return Session(connection, mode)


def read_version(path: str) -> int | None:
    """Read the database's `PRAGMA user_version`.

    Returns:
        The version stamped on the database, or None when `path` is not a readable
        sqlite database.
    """
    if not Path(path).is_file():
        return None
    connection = sqlite3.connect(path)
    try:
        (version,) = connection.execute("PRAGMA user_version").fetchone()
        return int(version)
    except sqlite3.Error:
        return None
    finally:
        connection.close()


class Session:
    """One connection and one transaction over a sqlite database.

    Used as a context manager: the transaction commits on a clean exit and rolls back
    on an exception, and the connection closes either way. Statements are literals
    supplied by the caller.
    """

    def __init__(self, connection: sqlite3.Connection, mode: SessionMode) -> None:
        self._connection = connection
        self._mode = mode

    def __enter__(self) -> "Session":
        # Foreign keys are per-connection, off by default, and silently ignored inside
        # a transaction, so this has to happen before the BEGIN.
        self._connection.execute("PRAGMA foreign_keys = ON")
        # A transaction that reads before it writes can never take the write lock once
        # another writer has committed (SQLITE_BUSY_SNAPSHOT), however long it waits.
        if self._mode is SessionMode.READ_AND_WRITE:
            self._connection.execute("BEGIN IMMEDIATE")
        else:
            self._connection.execute("BEGIN")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        try:
            self._connection.execute("ROLLBACK" if exc_type else "COMMIT")
        finally:
            self._connection.close()

    def create(self, schema: TableSchema) -> None:
        """Run the schema's CREATE statement."""
        self._connection.execute(schema.create)

    def insert(self, table: Table) -> None:
        """Insert every row of `table`."""
        self._connection.executemany(table.schema.insert, table.rows)

    def has_table(self, name: str) -> bool:
        """Whether the database holds a table called `name`."""
        return bool(self.query(_TABLE_EXISTS, (name,)))

    def insert_row(self, statement: str, params: Sequence[object] = ()) -> int:
        """Run an insert and return the new row's id."""
        return int(self._connection.execute(statement, tuple(params)).lastrowid or 0)

    def execute(self, statement: str, params: Sequence[object] = ()) -> None:
        """Run one statement, binding `params` as its `?` placeholders."""
        self._connection.execute(statement, tuple(params))

    def query(
        self, statement: str, params: Sequence[object] = ()
    ) -> list[tuple[Any, ...]]:
        """Run `statement` with `params` bound, and return every row it selects."""
        return self._connection.execute(statement, tuple(params)).fetchall()

    def read_version(self) -> int:
        """Read the database's `PRAGMA user_version` (0 on a new database)."""
        (version,) = self._connection.execute("PRAGMA user_version").fetchone()
        return int(version)

    def set_version(self, version: int) -> None:
        """Stamp the database's `PRAGMA user_version`."""
        self._connection.execute(f"PRAGMA user_version = {int(version)}")

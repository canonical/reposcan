# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Read and write tabular data as a sqlite database.

A `TableSchema` carries a table's name, column names, and literal CREATE/INSERT
statements to run. A `Table` pairs a schema with its rows. Callers serialize their own
values. All reads and writes occur within a `Session`.
"""

import logging
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any

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


def connect(path: str) -> tuple["Session | None", str | None]:
    """A session on the database at `path`, or None and an error message.

    Creates the file when it is absent. Returns errors rather than raising.

    sqlite serializes writers. Write-ahead logging lets readers work while a write is in
    flight, and the busy timeout makes a second writer wait rather than fail.
    """
    try:
        # isolation_level=None turns off sqlite3's implicit transaction handling, so
        # the session's own BEGIN/COMMIT are the only transaction boundaries.
        connection = sqlite3.connect(
            path, isolation_level=None, timeout=BUSY_TIMEOUT_SECONDS
        )
        # Not available on every filesystem (notably NFS); sqlite reports the mode it
        # settled on, and the rollback journal it falls back to is still correct.
        (mode,) = connection.execute("PRAGMA journal_mode = WAL").fetchone()
        if str(mode).lower() != "wal":
            logger.debug("%s is journalled as %s, not wal", path, mode)
    except sqlite3.Error as exc:
        return None, f"could not open {path}: {exc}"
    return Session(connection), None


def read_version(path: str) -> int | None:
    """The database's `PRAGMA user_version`, or None if `path` is not a database."""
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

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def __enter__(self) -> "Session":
        # Foreign keys are per-connection, off by default, and silently ignored inside
        # a transaction, so this has to happen before the BEGIN.
        self._connection.execute("PRAGMA foreign_keys = ON")
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
        """Run the schema's CREATE statement, exactly as written.

        Consider adding `IF NOT EXISTS` to `schema.create`
        """
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
        """Every row `statement` selects, binding `params` as its `?` placeholders."""
        return self._connection.execute(statement, tuple(params)).fetchall()

    def version(self) -> int:
        """The database's `PRAGMA user_version`, which is 0 on a new database."""
        (version,) = self._connection.execute("PRAGMA user_version").fetchone()
        return int(version)

    def set_version(self, version: int) -> None:
        """Stamp the database's `PRAGMA user_version`."""
        self._connection.execute(f"PRAGMA user_version = {int(version)}")

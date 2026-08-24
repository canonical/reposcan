# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Read and write tabular data as a sqlite database.

A generic utility with no domain knowledge. A `TableSchema` carries a table's name,
column names, and the literal CREATE/INSERT/SELECT statements to run. A `Table` pairs
a schema with its rows. Callers serialize their own values. `read` returns a table's
rows in insertion order, or None when the table (or the database) is not there.
"""

import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass

# The 16-byte header every sqlite 3 database file starts with.
_MAGIC = b"SQLite format 3\x00"


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
    select: str

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
    rows: Sequence[tuple[str, ...]]


def is_sqlite(data: bytes) -> bool:
    """Whether `data` begins with the sqlite database file header."""
    return data[:16] == _MAGIC


def write(path: str, table: Table) -> None:
    """Create `table` and insert its rows into the sqlite database at `path`.

    Creates the database file when absent and adds the table to it, so a report of
    several tables is written by calling this once per table.
    """
    connection = sqlite3.connect(path)
    try:
        connection.execute(table.schema.create)
        connection.executemany(table.schema.insert, table.rows)
        connection.commit()
    finally:
        connection.close()


def read(path: str, schema: TableSchema) -> Table | None:
    """The `schema`'s table with its rows in insertion order, or None.

    Returns None when the table does not exist or `path` is not a sqlite database.
    """
    connection = sqlite3.connect(path)
    try:
        return Table(schema, connection.execute(schema.select).fetchall())
    except sqlite3.Error:
        return None
    finally:
        connection.close()

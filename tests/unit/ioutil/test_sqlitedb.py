# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the generic sqlite tabular store (repo_scanner.ioutil.sqlitedb)."""

import os
import sqlite3
import tempfile

import pytest

from repo_scanner.ioutil.sqlitedb import Table, TableSchema, is_sqlite, read, write

_ITEMS = TableSchema(
    name="items",
    columns=("id", "name"),
    create="CREATE TABLE items (id TEXT, name TEXT)",
    insert="INSERT INTO items VALUES (?, ?)",
    select="SELECT * FROM items ORDER BY rowid",
)
_PRESENT = TableSchema(
    name="present",
    columns=("a",),
    create="CREATE TABLE present (a TEXT)",
    insert="INSERT INTO present VALUES (?)",
    select="SELECT * FROM present ORDER BY rowid",
)
_ABSENT = TableSchema(
    name="absent",
    columns=("a",),
    create="CREATE TABLE absent (a TEXT)",
    insert="INSERT INTO absent VALUES (?)",
    select="SELECT * FROM absent ORDER BY rowid",
)


def test_is_sqlite_detects_the_header() -> None:
    assert is_sqlite(b"SQLite format 3\x00rest of the file")
    assert not is_sqlite(b'{"bomFormat": "CycloneDX"}')


def test_write_then_read_round_trips_rows_in_insertion_order() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "x.db")
        write(path, Table(_ITEMS, [("2", "b"), ("1", "a")]))
        table = read(path, _ITEMS)
    assert table is not None
    assert table.rows == [("2", "b"), ("1", "a")]  # stored order, not sorted


def test_read_returns_none_for_a_missing_table_or_non_database() -> None:
    with tempfile.TemporaryDirectory() as directory:
        db = os.path.join(directory, "x.db")
        write(db, Table(_PRESENT, [("1",)]))
        assert read(db, _ABSENT) is None  # table not in the database

        not_a_db = os.path.join(directory, "note.txt")
        with open(not_a_db, "w") as handle:
            handle.write("not a database")
        assert read(not_a_db, _PRESENT) is None
        # reposcan catches/handles sqlite3 exceptions
        assert not isinstance(read(not_a_db, _PRESENT), sqlite3.Error)


def test_table_schema_rejects_placeholder_count_mismatch() -> None:
    with pytest.raises(ValueError):
        TableSchema(
            name="bad",
            columns=("a", "b"),
            create="CREATE TABLE bad (a TEXT, b TEXT)",
            insert="INSERT INTO bad VALUES (?)",  # one placeholder for two columns
            select="SELECT * FROM bad",
        )

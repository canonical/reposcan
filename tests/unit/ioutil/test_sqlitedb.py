# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the generic sqlite tabular store (repo_scanner.ioutil.sqlitedb)."""

import os
import sqlite3
import tempfile

import pytest

from repo_scanner.ioutil.sqlitedb import (
    Table,
    TableSchema,
    connect,
    is_sqlite,
    read_version,
)

_ITEMS = TableSchema(
    name="items",
    columns=("id", "name"),
    create="CREATE TABLE items (id TEXT, name TEXT)",
    insert="INSERT INTO items VALUES (?, ?)",
    select="SELECT * FROM items ORDER BY rowid",
)


def test_is_sqlite_detects_the_header() -> None:
    assert is_sqlite(b"SQLite format 3\x00rest of the file")
    assert not is_sqlite(b'{"bomFormat": "CycloneDX"}')


_PARENT = TableSchema(
    name="parent",
    columns=("id",),
    create="CREATE TABLE parent (id INTEGER PRIMARY KEY)",
    insert="INSERT INTO parent VALUES (?)",
    select="SELECT * FROM parent ORDER BY rowid",
)
_CHILD = TableSchema(
    name="child",
    columns=("parent_id",),
    create="CREATE TABLE child (parent_id INTEGER REFERENCES parent(id))",
    insert="INSERT INTO child VALUES (?)",
    select="SELECT * FROM child ORDER BY rowid",
)


def test_a_session_commits_on_a_clean_exit_and_rolls_back_on_an_error() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "x.db")

        session, error = connect(path)
        assert session is not None and error is None
        with session:
            session.create(_ITEMS)
            session.insert(Table(_ITEMS, [("1", "kept")]))

        session, _ = connect(path)
        assert session is not None
        with pytest.raises(RuntimeError), session:
            session.insert(Table(_ITEMS, [("2", "discarded")]))
            raise RuntimeError("boom")

        session, _ = connect(path)
        assert session is not None
        with session:
            assert session.query(_ITEMS.select) == [("1", "kept")]


def test_a_session_binds_parameters_and_reports_the_inserted_row_id() -> None:
    with tempfile.TemporaryDirectory() as directory:
        session, _ = connect(os.path.join(directory, "x.db"))
        assert session is not None
        with session:
            session.create(_ITEMS)
            first = session.insert_row(_ITEMS.insert, ("1", "a"))
            second = session.insert_row(_ITEMS.insert, ("2", "b"))
            assert second > first
            selected = session.query("SELECT name FROM items WHERE id = ?", ("2",))
    assert selected == [("b",)]


def test_has_table_reports_whether_a_table_is_there() -> None:
    with tempfile.TemporaryDirectory() as directory:
        session, _ = connect(os.path.join(directory, "x.db"))
        assert session is not None
        with session:
            assert not session.has_table("items")
            session.create(_ITEMS)
            assert session.has_table("items")


def test_a_session_enforces_foreign_keys() -> None:
    with tempfile.TemporaryDirectory() as directory:
        session, _ = connect(os.path.join(directory, "x.db"))
        assert session is not None
        with pytest.raises(sqlite3.IntegrityError), session:
            session.create(_PARENT)
            session.create(_CHILD)
            session.insert(Table(_CHILD, [(99,)]))  # no such parent


def test_the_schema_version_round_trips_and_is_absent_for_a_non_database() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "x.db")
        session, _ = connect(path)
        assert session is not None
        with session:
            assert session.version() == 0  # a new database starts at zero
            session.set_version(3)
        assert read_version(path) == 3

        assert read_version(os.path.join(directory, "missing.db")) is None

        not_a_db = os.path.join(directory, "note.txt")
        with open(not_a_db, "w") as handle:
            handle.write("not a database")
        assert read_version(not_a_db) is None


def test_connect_reports_a_failure_instead_of_raising() -> None:
    with tempfile.TemporaryDirectory() as directory:
        # A directory is not a file sqlite can open, so connect must explain itself.
        session, error = connect(directory)
    assert session is None
    assert error is not None and directory in error

# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the generic sqlite tabular store (reposcan.db.sqlite)."""

import os
import shutil
import sqlite3
import tempfile

import pytest

from reposcan.db.sqlite import (
    SessionMode,
    Table,
    TableSchema,
    connect,
    is_sqlite,
    read_version,
)
from reposcan.result import is_err

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
)
_CHILD = TableSchema(
    name="child",
    columns=("parent_id",),
    create="CREATE TABLE child (parent_id INTEGER REFERENCES parent(id))",
    insert="INSERT INTO child VALUES (?)",
)


def test_a_session_commits_on_a_clean_exit_and_rolls_back_on_an_error() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "x.db")

        session = connect(path, SessionMode.READ_AND_WRITE)
        assert not is_err(session)
        with session:
            session.create(_ITEMS)
            session.insert(Table(_ITEMS, [("1", "kept")]))

        session = connect(path, SessionMode.READ_AND_WRITE)
        assert not is_err(session)
        with pytest.raises(RuntimeError), session:
            session.insert(Table(_ITEMS, [("2", "discarded")]))
            raise RuntimeError("the caller failed mid-transaction")

        session = connect(path, SessionMode.READ)
        assert not is_err(session)
        with session:
            assert session.query(_ITEMS.select or "") == [("1", "kept")]


def test_a_session_binds_parameters_and_reports_the_inserted_row_id() -> None:
    with tempfile.TemporaryDirectory() as directory:
        session = connect(os.path.join(directory, "x.db"), SessionMode.READ_AND_WRITE)
        assert not is_err(session)
        with session:
            session.create(_ITEMS)
            first = session.insert_row(_ITEMS.insert, ("1", "a"))
            second = session.insert_row(_ITEMS.insert, ("2", "b"))
            assert second > first
            selected = session.query("SELECT name FROM items WHERE id = ?", ("2",))
    assert selected == [("b",)]


def test_has_table_reports_whether_a_table_is_there() -> None:
    with tempfile.TemporaryDirectory() as directory:
        session = connect(os.path.join(directory, "x.db"), SessionMode.READ_AND_WRITE)
        assert not is_err(session)
        with session:
            assert not session.has_table("items")
            session.create(_ITEMS)
            assert session.has_table("items")


def test_a_session_enforces_foreign_keys() -> None:
    with tempfile.TemporaryDirectory() as directory:
        session = connect(os.path.join(directory, "x.db"), SessionMode.READ_AND_WRITE)
        assert not is_err(session)
        with pytest.raises(sqlite3.IntegrityError), session:
            session.create(_PARENT)
            session.create(_CHILD)
            session.insert(Table(_CHILD, [(99,)]))  # no such parent


def test_the_schema_version_round_trips_and_is_absent_for_a_non_database() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "x.db")
        session = connect(path, SessionMode.READ_AND_WRITE)
        assert not is_err(session)
        with session:
            assert session.read_version() == 0  # a new database starts at zero
            session.set_version(3)
        assert read_version(path) == 3

        assert read_version(os.path.join(directory, "missing.db")) is None

        not_a_db = os.path.join(directory, "note.txt")
        with open(not_a_db, "w") as handle:
            handle.write("not a database")
        assert read_version(not_a_db) is None


def test_reading_the_version_never_changes_the_file() -> None:
    with tempfile.TemporaryDirectory() as directory:
        live = os.path.join(directory, "live.db")
        # isolation_level=None commits each statement as soon as it runs.
        writer = sqlite3.connect(live, isolation_level=None)
        # Under WAL, a committed change goes into the "-wal" log beside the file, and
        # reaches the file itself only when the log is folded in (a checkpoint).
        writer.execute("PRAGMA journal_mode = WAL")
        writer.execute("PRAGMA user_version = 3")
        # Copied while the writer is still open, as a database taken from a running
        # CI job could be: the copy's version 3 exists only in its log.
        copy = os.path.join(directory, "copy.db")
        shutil.copy(live, copy)
        shutil.copy(live + "-wal", copy + "-wal")
        # Closing checkpoints live.db's own log; the copy and its log are untouched.
        writer.close()
        with open(copy, "rb") as handle:
            before = handle.read()

        # The version can only have come from the copy's log. A read-write
        # connection would also fold that log into the file as it closes, changing
        # the file's bytes; a read-only one must leave them as they were.
        assert read_version(copy) == 3
        with open(copy, "rb") as handle:
            assert handle.read() == before


def test_connect_reports_a_failure_instead_of_raising() -> None:
    with tempfile.TemporaryDirectory() as directory:
        # A directory is not a file sqlite can open, so connect must explain itself.
        opened = connect(directory, SessionMode.READ_AND_WRITE)
    assert is_err(opened) and directory in opened.msg


def test_a_read_session_reads_its_file_and_writes_nothing() -> None:
    with tempfile.TemporaryDirectory() as directory:
        missing = os.path.join(directory, "missing.db")
        assert is_err(connect(missing, SessionMode.READ))
        assert not os.path.exists(missing)

        # A name that would add URI parameters if it reached sqlite unescaped.
        path = os.path.join(directory, "items.db?mode=rwc#x")
        version = 7
        writer_result = connect(path, SessionMode.READ_AND_WRITE)
        assert not is_err(writer_result)
        with writer_result as writer:
            writer.create(_ITEMS)
            writer.set_version(version)
        reader_result = connect(path, SessionMode.READ)
        assert not is_err(reader_result)
        with reader_result as reader:
            # The file named, not one that its "?" cut short.
            assert reader.read_version() == version
            with pytest.raises(sqlite3.OperationalError, match="readonly"):
                reader.insert(Table(_ITEMS, [("1", "x")]))

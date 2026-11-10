# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the database schema (reposcan.db.schema)."""

import hashlib
import os
import shutil
import sqlite3
import tempfile
from pathlib import Path

from reposcan.db import schema
from reposcan.db.sqlite import SessionMode, connect
from reposcan.result import is_err

SCHEMA_VERSIONS = {
    1: "d6405205bac473bf1ec53cfad16b3abcf98c257491d9342e256cf984c6641bf0"
}


def _build_digest() -> str:
    """A digest over every statement that defines the database."""
    material = "\n".join(
        [*(table.create for table in schema.TABLES), *schema.INDEXES, *schema.VIEWS]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def test_the_schema_matches_the_version_that_describes_it() -> None:
    assert _build_digest() == SCHEMA_VERSIONS[schema.SCHEMA_VERSION], (
        "The schema has changed without an update to schema version"
    )


def test_a_database_to_read_must_be_a_whole_current_reposcan_database() -> None:
    with tempfile.TemporaryDirectory() as directory:
        current = os.path.join(directory, "current.db")
        session = connect(current, SessionMode.READ_AND_WRITE)
        assert not is_err(session)
        with session:
            schema.create_all(session)
        # Written by a reposcan with a newer schema.
        newer = os.path.join(directory, "newer.db")
        shutil.copy(current, newer)
        connection = sqlite3.connect(newer)
        connection.execute("PRAGMA user_version = 99")
        connection.close()
        # A view standing in for a table, as a crafted database could hold.
        posed = os.path.join(directory, "posed.db")
        shutil.copy(current, posed)
        connection = sqlite3.connect(posed)
        connection.execute("ALTER TABLE analysis RENAME TO analysis_rows")
        connection.execute("CREATE VIEW analysis AS SELECT * FROM analysis_rows")
        connection.commit()
        connection.close()
        text = os.path.join(directory, "notes.txt")
        Path(text).write_text("not a database")
        missing = os.path.join(directory, "missing.db")

        assert schema.confirm_usable(current, must_be_current=True) is None
        for path in (newer, posed, text, missing):
            assert is_err(schema.confirm_usable(path, must_be_current=True)), path
        assert not os.path.exists(missing)  # checking never creates the file

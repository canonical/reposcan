# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Ensure the database schema is not updated without updating to SCHEMA_VERSION."""

import hashlib

from repo_scanner.db import schema

SCHEMA_VERSIONS = {
    1: "d6405205bac473bf1ec53cfad16b3abcf98c257491d9342e256cf984c6641bf0"
}


def _digest() -> str:
    """A digest over every statement that defines the database."""
    material = "\n".join(
        [*(table.create for table in schema.TABLES), *schema.INDEXES, *schema.VIEWS]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def test_the_schema_matches_the_version_that_describes_it() -> None:
    assert _digest() == SCHEMA_VERSIONS[schema.SCHEMA_VERSION], (
        "The schema has changed without an update to schema version"
    )

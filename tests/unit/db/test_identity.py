# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for component identity and issue equivalence."""

from reposcan.db.identity import (
    IssueAttributes,
    derive_component_key,
    normalize_purl,
    same_issue,
)


def test_a_component_keeps_its_identity_across_a_version_bump() -> None:
    old = {"purl": "pkg:pypi/flask@2.0.0", "name": "flask", "version": "2.0.0"}
    new = {"purl": "pkg:pypi/flask@3.0.0", "name": "flask", "version": "3.0.0"}
    assert derive_component_key(old) == derive_component_key(new)
    other = {"purl": "pkg:pypi/django@3.0.0"}
    assert derive_component_key(old) != derive_component_key(other)


def test_components_without_a_purl_fall_back_to_coordinates_then_the_name() -> None:
    coords = {"type": "library", "group": "org.apache", "name": "log4j"}
    assert derive_component_key(coords) == derive_component_key(dict(coords))
    assert derive_component_key(coords) != derive_component_key({"name": "log4j"})
    assert derive_component_key({"name": "x"}) == derive_component_key({"name": "x"})


def test_normalize_purl_agrees_where_tools_differ_for_no_reason() -> None:
    base = "pkg:maven/org.apache/log4j-core"
    # Qualifiers, subpath, and version say nothing about which package this is.
    assert normalize_purl(f"{base}@2.17.1?type=jar#sub") == normalize_purl(base)
    # The type is always case-insensitive.
    assert normalize_purl("pkg:PyPI/Flask") == normalize_purl("pkg:pypi/flask")
    # PyPI treats a hyphen and an underscore in a name as the same character.
    assert normalize_purl("pkg:pypi/ruamel_yaml") == normalize_purl(
        "pkg:pypi/ruamel-yaml"
    )
    # Maven coordinates are case-sensitive, so they must not be folded.
    assert normalize_purl("pkg:maven/org.apache/Log4J") != normalize_purl(base)
    # An npm scope survives a round trip through percent-encoding.
    assert normalize_purl("pkg:npm/%40angular/core") == normalize_purl(
        "pkg:npm/@angular/core"
    )
    assert normalize_purl("not-a-purl") == ""


def _attributes(**kwargs: object) -> IssueAttributes:
    fields: dict = {"rule": "R1", "uri": "a.py", "line": "10"}
    fields.update(kwargs)
    return IssueAttributes(**fields)  # type: ignore[arg-type]


def test_a_report_that_gains_a_fingerprint_is_still_the_same_issue() -> None:
    known = _attributes()
    # The line hash was unreadable last analysis and is available now
    gained = _attributes(partial_fingerprints={"primaryLocationLineHash": "abc:1"})
    assert same_issue(known, gained)
    # And the reverse, when a tool stops emitting one.
    assert same_issue(gained, known)


def test_a_complete_fingerprint_always_wins() -> None:
    here = _attributes(uri="a.py", fingerprints={"secretHash/v1": "s"})
    moved = _attributes(uri="b.py", line="99", fingerprints={"secretHash/v1": "s"})
    assert same_issue(here, moved)

    other = _attributes(uri="a.py", fingerprints={"secretHash/v1": "different"})
    # A shared name with a different fingerprint is a different issue
    assert not same_issue(here, other)


def test_a_disagreeing_line_hash_beats_matching_position() -> None:
    before = _attributes(partial_fingerprints={"primaryLocationLineHash": "abc:1"})
    after = _attributes(partial_fingerprints={"primaryLocationLineHash": "xyz:1"})
    # Same rule and same place, but the line's content changed.
    assert not same_issue(before, after)


def test_position_matches_only_when_nothing_stronger_is_available() -> None:
    assert same_issue(_attributes(), _attributes())
    assert not same_issue(_attributes(), _attributes(line="11"))
    assert not same_issue(_attributes(), _attributes(uri="b.py"))
    assert not same_issue(_attributes(), _attributes(rule="R2"))


def test_a_scan_types_own_comparison_is_one_more_rule_in_the_list() -> None:
    # The same SCA rule is the same issue regardless of locatio
    advisory = IssueAttributes("CVE-2026-1", "poetry.lock", "12")
    moved = IssueAttributes("CVE-2026-1", "pyproject.toml", "3")
    # one SAST rule firing in two places is different
    assert same_issue(advisory, moved, "sca")
    assert not same_issue(advisory, moved, "sast")


def test_a_complete_fingerprint_is_not_vetoed_by_a_partial_one() -> None:
    known = _attributes(fingerprints={"secretHash/v1": "s"})
    known.partial_fingerprints["primaryLocationLineHash"] = "abc:1"
    incoming = _attributes(line="90", fingerprints={"secretHash/v1": "s"})
    incoming.partial_fingerprints["primaryLocationLineHash"] = "xyz:1"
    assert same_issue(known, incoming)


def test_position_alone_loses_to_a_fingerprint_that_disagrees() -> None:
    known = _attributes(uri="a.py", line="10")
    known.partial_fingerprints["primaryLocationLineHash"] = "abc:1"
    incoming = _attributes(uri="a.py", line="10")
    incoming.partial_fingerprints["primaryLocationLineHash"] = "xyz:1"
    # Same rule, file, and line, but the line's content changed.
    assert not same_issue(known, incoming)

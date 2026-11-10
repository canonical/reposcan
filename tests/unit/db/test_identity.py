# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for component identity and issue equivalence."""

from dataclasses import dataclass

from reposcan.db.identity import (
    IssueAttributes,
    derive_component_key,
    is_same_issue,
    normalize_purl,
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


@dataclass(frozen=True)
class _EquivalenceCase:
    category: str
    known: IssueAttributes
    incoming: IssueAttributes
    should_be_same_issue: bool
    why: str


_EQUIVALENCE_CASES = [
    _EquivalenceCase(
        why=(
            "SAST findings with the same rule, uri, and line are the same issue so "
            "long as no fingerprints disagree."
        ),
        category="sast",
        known=IssueAttributes(rule="R1", uri="a.py", line="10"),
        incoming=IssueAttributes(rule="R1", uri="a.py", line="10"),
        should_be_same_issue=True,
    ),
    _EquivalenceCase(
        why=(
            "SAST findings with the same rule, uri, and line are the same issue so "
            "long as no fingerprints disagree, and a fingerprint on only one finding "
            "does not disagree. Example: the tool could not read the line last time, "
            "so only the newer finding has a line hash."
        ),
        category="sast",
        known=IssueAttributes(rule="R1", uri="a.py", line="10"),
        incoming=IssueAttributes(
            rule="R1",
            uri="a.py",
            line="10",
            partial_fingerprints={"primaryLocationLineHash": "5f2c9e1a:1"},
        ),
        should_be_same_issue=True,
    ),
    _EquivalenceCase(
        why=(
            "SAST findings with the same rule, uri, and line are the same issue so "
            "long as no fingerprints disagree, and a fingerprint on only one finding "
            "does not disagree. Example: the tool stopped emitting a line hash, so "
            "only the older finding has one."
        ),
        category="sast",
        known=IssueAttributes(
            rule="R1",
            uri="a.py",
            line="10",
            partial_fingerprints={"primaryLocationLineHash": "5f2c9e1a:1"},
        ),
        incoming=IssueAttributes(rule="R1", uri="a.py", line="10"),
        should_be_same_issue=True,
    ),
    _EquivalenceCase(
        why=(
            "SAST findings with the same rule and uri on different lines are not the "
            "same issue unless some fingerprint matches."
        ),
        category="sast",
        known=IssueAttributes(rule="R1", uri="a.py", line="10"),
        incoming=IssueAttributes(rule="R1", uri="a.py", line="11"),
        should_be_same_issue=False,
    ),
    _EquivalenceCase(
        why=(
            "SAST findings with the same rule in different uris are not the same "
            "issue unless a full fingerprint matches."
        ),
        category="sast",
        known=IssueAttributes(rule="R1", uri="a.py", line="10"),
        incoming=IssueAttributes(rule="R1", uri="b.py", line="10"),
        should_be_same_issue=False,
    ),
    _EquivalenceCase(
        why="Findings with different rules are never the same issue.",
        category="sast",
        known=IssueAttributes(rule="R1", uri="a.py", line="10"),
        incoming=IssueAttributes(rule="R2", uri="a.py", line="10"),
        should_be_same_issue=False,
    ),
    _EquivalenceCase(
        why=(
            "SAST findings with the same rule, uri, and line are the same issue so "
            "long as no full fingerprints disagree, even with a disagreeing partial "
            "fingerprint. Example: a variable on the line was renamed, changing the "
            "line hash."
        ),
        category="sast",
        known=IssueAttributes(
            rule="R1",
            uri="a.py",
            line="10",
            partial_fingerprints={"primaryLocationLineHash": "5f2c9e1a:1"},
        ),
        incoming=IssueAttributes(
            rule="R1",
            uri="a.py",
            line="10",
            partial_fingerprints={"primaryLocationLineHash": "c07d3b44:1"},
        ),
        should_be_same_issue=True,
    ),
    _EquivalenceCase(
        why=(
            "Findings with the same rule, uri, and a matching partial fingerprint are "
            "not the same issue if their full fingerprints disagree. Fingerprints are "
            "expected to be definitive."
        ),
        category="sast",
        known=IssueAttributes(
            rule="R1",
            uri="a.py",
            line="10",
            fingerprints={"matchBasedId/v1": "a"},
            partial_fingerprints={"primaryLocationLineHash": "5f2c9e1a:1"},
        ),
        incoming=IssueAttributes(
            rule="R1",
            uri="a.py",
            line="12",
            fingerprints={"matchBasedId/v1": "b"},
            partial_fingerprints={"primaryLocationLineHash": "5f2c9e1a:1"},
        ),
        should_be_same_issue=False,
    ),
    _EquivalenceCase(
        why=(
            "SCA findings with the same rule are the same issue, regardless of other "
            "attributes. Example: one CVE advisory reported against two manifest files."
        ),
        category="sca",
        known=IssueAttributes(rule="CVE-2026-1", uri="poetry.lock", line="12"),
        incoming=IssueAttributes(rule="CVE-2026-1", uri="pyproject.toml", line="3"),
        should_be_same_issue=True,
    ),
    _EquivalenceCase(
        why=(
            "SAST findings with the same rule in different uris are not the same "
            "issue unless a full fingerprint matches."
        ),
        category="sast",
        known=IssueAttributes(rule="sast-1", uri="poetry.lock", line="12"),
        incoming=IssueAttributes(rule="sast-1", uri="pyproject.toml", line="3"),
        should_be_same_issue=False,
    ),
    _EquivalenceCase(
        why=(
            "Secrets findings with the same rule and a matching secretHash are the "
            "same issue. Example: the same secret copied to a backup file."
        ),
        category="secrets",
        known=IssueAttributes(
            rule="AWS", uri="a.env", line="10", fingerprints={"secretHash/v1": "s"}
        ),
        incoming=IssueAttributes(
            rule="AWS",
            uri="backup/a.env",
            line="99",
            fingerprints={"secretHash/v1": "s"},
        ),
        should_be_same_issue=True,
    ),
    _EquivalenceCase(
        why=(
            "Secrets findings with the same rule and a matching secretHash are the "
            "same issue, even if their partial fingerprints disagree. Example: the "
            "line holding the secret moved and was edited."
        ),
        category="secrets",
        known=IssueAttributes(
            rule="AWS",
            uri="a.env",
            line="10",
            fingerprints={"secretHash/v1": "s"},
            partial_fingerprints={"primaryLocationLineHash": "5f2c9e1a:1"},
        ),
        incoming=IssueAttributes(
            rule="AWS",
            uri="a.env",
            line="90",
            fingerprints={"secretHash/v1": "s"},
            partial_fingerprints={"primaryLocationLineHash": "c07d3b44:1"},
        ),
        should_be_same_issue=True,
    ),
    _EquivalenceCase(
        why=(
            "Secrets findings with the same rule, uri, and line are not the same "
            "issue if their secretHash fingerprints disagree."
        ),
        category="secrets",
        known=IssueAttributes(
            rule="AWS", uri="a.env", line="10", fingerprints={"secretHash/v1": "s"}
        ),
        incoming=IssueAttributes(
            rule="AWS", uri="a.env", line="10", fingerprints={"secretHash/v1": "t"}
        ),
        should_be_same_issue=False,
    ),
    _EquivalenceCase(
        why=(
            "Two secrets findings with the same rule, uri, and line are not the same "
            "if any of their fingerprints disagree. Example: a certificate rotated in "
            "place, which may share the line hash of the former finding, since all "
            "certs have the same 'BEGIN' format."
        ),
        category="secrets",
        known=IssueAttributes(
            rule="PrivateKey",
            uri="deploy/id_rsa",
            line="1",
            fingerprints={"secretHash/v1": "old"},
            partial_fingerprints={"primaryLocationLineHash": "5f2c9e1a:1"},
        ),
        incoming=IssueAttributes(
            rule="PrivateKey",
            uri="deploy/id_rsa",
            line="1",
            fingerprints={"secretHash/v1": "new"},
            partial_fingerprints={"primaryLocationLineHash": "5f2c9e1a:1"},
        ),
        should_be_same_issue=False,
    ),
    _EquivalenceCase(
        why=(
            "A secrets finding with the same rule, uri, and a matching partial "
            "fingerprint are the same issue, so long as no fingerprints disagree. "
            "(Note the 'disagreeing' secretHash fingerprints have different version "
            "tags.)"
        ),
        category="secrets",
        known=IssueAttributes(
            rule="AWS",
            uri="a.env",
            line="10",
            fingerprints={"secretHash/v1": "s"},
            partial_fingerprints={"primaryLocationLineHash": "5f2c9e1a:1"},
        ),
        incoming=IssueAttributes(
            rule="AWS",
            uri="a.env",
            line="12",
            fingerprints={"secretHash/v2": "t"},
            partial_fingerprints={"primaryLocationLineHash": "5f2c9e1a:1"},
        ),
        should_be_same_issue=True,
    ),
]


def test_equivalence_cases() -> None:
    wrong = []
    for case in _EQUIVALENCE_CASES:
        same_issue = is_same_issue(case.known, case.incoming, case.category)
        if same_issue != case.should_be_same_issue:
            wrong.append(f"expected same_issue={case.should_be_same_issue}: {case.why}")
    assert not wrong, "\n".join(wrong)

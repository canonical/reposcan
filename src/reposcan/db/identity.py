# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Identities for components, and equivalence for issues.

Every component key carries the derivation version it was made with. An issue has no
derived key; reports are compared against each other by EQUIVALENCE_RULES.
"""

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, unquote

from reposcan.scans import sarif

IDENTITY_VERSION = 1

# purl types whose namespace and name are case-insensitive, per their type
# definitions. Note that maven coordinates are case-sensitive.
_LOWERCASE_TYPES = frozenset({"bitbucket", "github", "golang", "npm", "pypi"})


@dataclass(frozen=True)
class IssueAttributes:
    """Attributes used to determine if two reports are the same issue."""

    rule: str
    uri: str
    line: str
    fingerprints: dict[str, str] = field(default_factory=dict)
    partial_fingerprints: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_result(cls, result: sarif.SarifResult) -> "IssueAttributes":
        """Pull issue attributes from a SarifResult."""
        return cls(
            rule=result.rule_id,
            uri=result.uri,
            line=str(result.line) if result.line else "",
            fingerprints={
                str(name): str(value)
                for name, value in result.result.get("fingerprints", {}).items()
                if value
            },
            partial_fingerprints={
                str(name): str(value)
                for name, value in result.result.get("partialFingerprints", {}).items()
                if value
            },
        )


@dataclass(frozen=True)
class EquivalenceRule:
    """A rule that evaluates whether two reports are about the same issue.

    Each rule is an instance of this class, which defines several instance attributes
    that are effectively boolean conditions that are and'ed together. If all of a
    rule's instance attributes evaluate to true, the rule matches.

    Rules are tried independently, and a True from any one rule must be sufficient
    to determine equivalent (i.e., rules are evaluated with
    `any(rule.holds(k, i) for rule in rules)`)

    Clauses:
        agree_on: a list of fields that both reports must agree on.
        fp_match: the reports must agree on at least one key:value pair of their
            `fingerprints`. Compared by exact name, so `secretHash` and
            `secretHash/v1` are different computations and one says nothing about the
            other.
        partial_fp_match: the same, over `partialFingerprints`.
        no_fp_conflict: the reports' fingerprint maps must not disagree on the value
            of any fingerprint.
        category: the scan type this rule is written for, if only one.
    """

    agree_on: tuple[str, ...] = ()
    fp_match: bool = False
    partial_fp_match: bool = False
    no_fp_conflict: bool = False
    category: str = ""

    def holds(
        self, known: IssueAttributes, incoming: IssueAttributes, category: str
    ) -> bool:
        """Evalute whether two reports concern the same issue."""
        if self.category and self.category != category:
            return False
        if any(
            getattr(known, name) != getattr(incoming, name) for name in self.agree_on
        ):
            return False
        fp_agrees, fp_conflicts = _compare_fingerprints(
            known.fingerprints, incoming.fingerprints
        )
        partial_agrees, partial_conflicts = _compare_fingerprints(
            known.partial_fingerprints, incoming.partial_fingerprints
        )
        if self.fp_match and not fp_agrees:
            return False
        if self.partial_fp_match and not partial_agrees:
            return False
        return not (self.no_fp_conflict and (fp_conflicts or partial_conflicts))


# Two reports are about the same issue if any rule evaluates true. A full fingerprint
# identifies a result outright. A partial fp is trusted within a file.
# Position is the last resort, and only if no fingerprint contradicts it.
EQUIVALENCE_RULES: tuple[EquivalenceRule, ...] = (
    EquivalenceRule(agree_on=("rule",), fp_match=True),
    # An SCA advisory is reported once per vulnerability, so its rule -- usually the
    # CVE -- is the whole identity; where it was found and how it was fingerprinted
    # vary between tools without meaning anything.
    EquivalenceRule(agree_on=("rule",), category="sca"),
    EquivalenceRule(agree_on=("rule", "uri"), partial_fp_match=True),
    EquivalenceRule(agree_on=("rule", "uri", "line"), no_fp_conflict=True),
)


def same_issue(
    known: IssueAttributes, incoming: IssueAttributes, category: str = ""
) -> bool:
    """Whether `incoming` is another report of `known`.

    `category` is the category of scan that produced the report.
    """
    return any(rule.holds(known, incoming, category) for rule in EQUIVALENCE_RULES)


def _compare_fingerprints(
    recorded: Mapping[str, str], reported: Mapping[str, str]
) -> tuple[bool, bool]:
    """How one kind of fingerprint compares between two reports.

    Returns:
        (has_a_match, has_a_conflict) Both are False when they have no shared
        keys.
    """
    shared = set(recorded) & set(reported)
    agrees = any(recorded[name] == reported[name] for name in shared)
    return agrees, bool(shared) and not agrees


def derive_component_key(component: Mapping[str, Any]) -> str:
    """A component's identity, derived from its package url if it has one.

    Component version is never included. A dependency that moves from 2.14.1 to 2.17.1
    is the same dependency (the new version sighting is still recorded).
    """
    purl = normalize_purl(str(component.get("purl", "")))
    if purl:
        return _digest("purl", purl)
    type_ = str(component.get("type", ""))
    group = str(component.get("group", ""))
    name = str(component.get("name", ""))
    if type_ or group:
        return _digest("coords", type_, group, name)
    return _digest("name", name)


def normalize_purl(purl: str) -> str:
    """A package url reduced to a comparable, versionless form.

    Two tools naming one package should produce one key, regardless of formatting of
    qualifiers such as `?type=jar` or `?arch=amd64`.

    Returns:
        The comparable form, or an empty string when `purl` is not a package url.
    """
    text = purl.strip()
    if not text.startswith("pkg:"):
        return ""
    text = text[len("pkg:") :]
    # None of the subpath, the qualifiers, or the version says which package this is.
    text = text.split("#", 1)[0].split("?", 1)[0]
    # The version is separated by an "@" in the last segment only. An npm scope puts
    # an "@" earlier in the path, and a scan of the whole string would eat it.
    head, slash, last = text.rpartition("/")
    version_at = last.rfind("@")
    if version_at != -1:
        text = head + slash + last[:version_at]
    type_, slash, rest = text.partition("/")
    type_ = type_.lower()  # the type is case-insensitive for every purl type
    if not slash:
        return type_
    segments = [unquote(segment) for segment in rest.split("/") if segment]
    if type_ in _LOWERCASE_TYPES:
        segments = [segment.lower() for segment in segments]
    if type_ == "pypi":
        # PyPI treats a hyphen and an underscore in a name as the same character.
        segments = [segment.replace("_", "-") for segment in segments]
    encoded = "/".join(quote(segment, safe="") for segment in segments)
    return f"{type_}/{encoded}"


def _digest(scheme: str, *parts: str) -> str:
    """A digest over `parts`, tagged with its scheme and the derivation version.

    The parts are delimited, so no rearrangement of one field's content can imitate
    another's.
    """
    material = "|".join((str(IDENTITY_VERSION), scheme, *parts))
    return hashlib.sha256(material.encode("utf-8", "surrogatepass")).hexdigest()

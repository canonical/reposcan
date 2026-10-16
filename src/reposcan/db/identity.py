# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Identities for components, and equivalence for issues.

A component has a derived key. An issue has none, so reports are compared against
each other by EQUIVALENCE_RULES.
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

    Each rule is an instance of this class, whose attributes are conditions that are
    and'ed together; an unset condition is not checked. If every set condition holds,
    the rule matches.

    Rules are tried independently, and a True from any one rule must be sufficient
    to determine equivalence (i.e., rules are evaluated with
    `any(rule.holds(k, i) for rule in rules)`).

    Conditions:
        category: the scan type this rule is written for, if only one.
        same_rule, same_uri, same_line: the reports agree on that field.
        fingerprints_fully_match: every `fingerprints` entry the two reports share
            has the same value on both, i.e. no fingerprint contradicts the match.
            Holds when they share none.
        fingerprints_partially_match: at least one `fingerprints` entry the reports
            share has the same value on both. Names are compared exactly, so
            `secretHash` and `secretHash/v1` are different computations and one
            says nothing about the other.
        specific_fingerprints_match: each named fingerprint is on both reports, with
            the same value.
        partial_fingerprints_fully_match, partial_fingerprints_partially_match,
        specific_partial_fingerprints_match: the same, over `partialFingerprints`.
    """

    category: str = ""
    same_rule: bool = False
    same_uri: bool = False
    same_line: bool = False
    fingerprints_fully_match: bool = False
    fingerprints_partially_match: bool = False
    specific_fingerprints_match: tuple[str, ...] = ()
    partial_fingerprints_fully_match: bool = False
    partial_fingerprints_partially_match: bool = False
    specific_partial_fingerprints_match: tuple[str, ...] = ()

    def holds(
        self, known: IssueAttributes, incoming: IssueAttributes, category: str
    ) -> bool:
        """Evaluate whether two reports concern the same issue."""
        if self.category and self.category != category:
            return False
        if self.same_rule and known.rule != incoming.rule:
            return False
        if self.same_uri and known.uri != incoming.uri:
            return False
        if self.same_line and known.line != incoming.line:
            return False
        return _check_fingerprints(
            known.fingerprints,
            incoming.fingerprints,
            fully=self.fingerprints_fully_match,
            partially=self.fingerprints_partially_match,
            specific=self.specific_fingerprints_match,
        ) and _check_fingerprints(
            known.partial_fingerprints,
            incoming.partial_fingerprints,
            fully=self.partial_fingerprints_fully_match,
            partially=self.partial_fingerprints_partially_match,
            specific=self.specific_partial_fingerprints_match,
        )


# Two reports are about the same issue if any rule evaluates true. A full fingerprint
# identifies a result outright: a matching one is the same issue, and a disagreeing
# one is a different issue. A partial fp is trusted within a file, and position is
# the last resort, both only if no fingerprint contradicts them.
EQUIVALENCE_RULES: tuple[EquivalenceRule, ...] = (
    # A secret's hash is the secret itself: one leak, wherever it is seen.
    EquivalenceRule(category="secrets", specific_fingerprints_match=("secretHash/v1",)),
    EquivalenceRule(same_rule=True, fingerprints_partially_match=True),
    # An SCA advisory is reported once per vulnerability, so its rule -- usually the
    # CVE -- is the whole identity; where it was found and how it was fingerprinted
    # vary between tools without meaning anything.
    EquivalenceRule(category="sca", same_rule=True),
    # Two private keys rotated in place share an identical BEGIN line, so their line
    # hashes match; only their (disagreeing) secret hashes tell them apart.
    EquivalenceRule(
        same_rule=True,
        same_uri=True,
        partial_fingerprints_partially_match=True,
        fingerprints_fully_match=True,
    ),
    EquivalenceRule(
        same_rule=True,
        same_uri=True,
        same_line=True,
        fingerprints_fully_match=True,
        partial_fingerprints_fully_match=True,
    ),
)


def is_same_issue(
    known: IssueAttributes, incoming: IssueAttributes, category: str = ""
) -> bool:
    """Whether `incoming` is another report of `known`.

    `category` is the category of scan that produced the report.
    """
    return any(rule.holds(known, incoming, category) for rule in EQUIVALENCE_RULES)


def _check_fingerprints(
    recorded: Mapping[str, str],
    reported: Mapping[str, str],
    *,
    fully: bool,
    partially: bool,
    specific: tuple[str, ...],
) -> bool:
    """Check one kind of fingerprint against a rule's requested matches.

    Args:
        recorded: The known report's fingerprints of this kind.
        reported: The incoming report's fingerprints of this kind.
        fully: Require every shared fingerprint to agree.
        partially: Require at least one shared fingerprint to agree.
        specific: Require each named fingerprint on both reports, agreeing.
    """
    shared = set(recorded) & set(reported)
    agreeing = {name for name in shared if recorded[name] == reported[name]}
    if fully and agreeing != shared:
        return False
    if partially and not agreeing:
        return False
    return all(name in agreeing for name in specific)


def derive_component_key(component: Mapping[str, Any]) -> str:
    """Derive a component's identity from its package url.

    Component version is never included. A dependency that moves from 2.14.1 to 2.17.1
    is the same dependency (the new version sighting is still recorded).
    """
    purl = normalize_purl(str(component.get("purl", "")))
    if purl:
        return _build_digest("purl", purl)
    type_ = str(component.get("type", ""))
    group = str(component.get("group", ""))
    name = str(component.get("name", ""))
    if type_ or group:
        return _build_digest("coords", type_, group, name)
    return _build_digest("name", name)


def normalize_purl(purl: str) -> str:
    """Reduce a package url to a comparable, versionless form.

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


def _build_digest(scheme: str, *parts: str) -> str:
    """Create a digest from `parts`.

    The parts are delimited, so no rearrangement of one field's content can imitate
    another's, and IDENTITY_VERSION is mixed in, so changing how a key is derived
    changes every key derived that way.
    """
    material = "|".join((str(IDENTITY_VERSION), scheme, *parts))
    return hashlib.sha256(material.encode("utf-8", "surrogatepass")).hexdigest()

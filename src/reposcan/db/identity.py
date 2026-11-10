# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Identities for components, and equivalence for issues.

A component has a derived key. An issue has none, so reports are compared against
each other by EQUIVALENCE_RULESET.
"""

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol
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


class EquivalenceCondition(Protocol):
    """A test that determines whether two IssueAttributes refer to the same issue."""

    def holds(
        self, known: IssueAttributes, incoming: IssueAttributes, category: str
    ) -> bool: ...


class AnyOf:
    def __init__(self, *conditions: EquivalenceCondition) -> None:
        self.conditions = conditions

    def holds(
        self, known: IssueAttributes, incoming: IssueAttributes, category: str
    ) -> bool:
        return any(c.holds(known, incoming, category) for c in self.conditions)


class AllOf:
    def __init__(self, *conditions: EquivalenceCondition) -> None:
        self.conditions = conditions

    def holds(
        self, known: IssueAttributes, incoming: IssueAttributes, category: str
    ) -> bool:
        return all(c.holds(known, incoming, category) for c in self.conditions)


class SameRule:
    def holds(
        self, known: IssueAttributes, incoming: IssueAttributes, category: str
    ) -> bool:
        return known.rule == incoming.rule


class SameUri:
    def holds(
        self, known: IssueAttributes, incoming: IssueAttributes, category: str
    ) -> bool:
        return known.uri == incoming.uri


class SameLine:
    def holds(
        self, known: IssueAttributes, incoming: IssueAttributes, category: str
    ) -> bool:
        return known.line == incoming.line


class MatchingFingerprint:
    def __init__(self, *names: str) -> None:
        self.names: set[str] = set(names)  # empty: compare every fingerprint

    def holds(
        self, known: IssueAttributes, incoming: IssueAttributes, category: str
    ) -> bool:
        shared = known.fingerprints.keys() & incoming.fingerprints.keys()
        if self.names:
            shared &= self.names
        return len(shared) > 0 and any(
            known.fingerprints[name] == incoming.fingerprints[name] for name in shared
        )


class MatchingPartialFingerprint:
    def holds(
        self, known: IssueAttributes, incoming: IssueAttributes, category: str
    ) -> bool:
        shared = (
            known.partial_fingerprints.keys() & incoming.partial_fingerprints.keys()
        )
        return len(shared) > 0 and any(
            known.partial_fingerprints[name] == incoming.partial_fingerprints[name]
            for name in shared
        )


class InCategories:
    def __init__(self, *categories: str) -> None:
        self.categories: set[str] = set(categories)

    def holds(
        self, known: IssueAttributes, incoming: IssueAttributes, category: str
    ) -> bool:
        return category in self.categories


class NoFingerprintConflict:
    def holds(
        self, known: IssueAttributes, incoming: IssueAttributes, category: str
    ) -> bool:
        shared = known.fingerprints.keys() & incoming.fingerprints.keys()
        return all(
            known.fingerprints[name] == incoming.fingerprints[name] for name in shared
        )


class Not:
    def __init__(self, condition: EquivalenceCondition) -> None:
        self.condition = condition

    def holds(
        self, known: IssueAttributes, incoming: IssueAttributes, category: str
    ) -> bool:
        return not self.condition.holds(known, incoming, category)


# A full fingerprint identifies a result outright:
#   matching fp => same issue; disagreeing fp => different issue
# A partial fp is trusted within a file.
# Position is trusted only if no fingerprints disagree.
EQUIVALENCE_RULESET = AllOf(
    SameRule(),
    AnyOf(
        MatchingFingerprint(),
        # A secret is identified by its hash, regardless of other attributes.
        AllOf(InCategories("secrets"), MatchingFingerprint("secretHash/v1")),
        # An SCA advisory is reported once per vulnerability, so its rule -- usually
        # the CVE -- is the whole identity. Reported location is immaterial.
        InCategories("sca"),
        # Two private keys rotated in place share an identical BEGIN line, so their
        # line hashes match; only their (disagreeing) secret hashes tell them apart.
        AllOf(SameUri(), MatchingPartialFingerprint(), NoFingerprintConflict()),
        AllOf(SameUri(), SameLine(), NoFingerprintConflict()),
    ),
)


def is_same_issue(
    known: IssueAttributes, incoming: IssueAttributes, category: str = ""
) -> bool:
    """Whether `incoming` is another report of `known`.

    `category` is the category of scan that produced the report.
    """
    return EQUIVALENCE_RULESET.holds(known, incoming, category)


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

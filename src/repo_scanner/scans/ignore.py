# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""reposcan ignorefile.

A repository may carry a `.reposcan-ignore` file whose entries suppress classes of
findings. Each non-blank, non-comment line is three whitespace-separated fields:

    <tool>  <ruleId>  <path-glob>

`tool` is the scanner that reported the finding, or `*` for any; `ruleId` is the SARIF
rule id shown in the finding; and `path-glob` is a repository-root-relative glob (`*`
within a path segment, `**` across segments, `?` one character). A `#` starts a comment.
A finding is dropped when all three match.
"""

import logging
import re
from pathlib import Path
from typing import Any

from repo_scanner.scans import sarif
from repo_scanner.scans.model import Artifact

logger = logging.getLogger(__name__)

# The ignorefile reposcan looks for in a scanned repository by default.
DEFAULT_IGNORE_FILE = ".reposcan-ignore"


class IgnoreRule:
    """One ignorefile entry: suppress findings matching a tool, rule id, and path."""

    def __init__(self, tool: str, rule_id: str, path_glob: str) -> None:
        self.tool = tool
        self.rule_id = rule_id
        self.path_glob = path_glob
        self._pattern = _glob_to_regex(path_glob)

    def matches(self, rule_id: str, uri: str, tools: list[str]) -> bool:
        """Whether a finding (`rule_id`, `uri`, reporting `tools`) is ignored."""
        if rule_id != self.rule_id:
            return False
        if self.tool != "*" and self.tool not in tools:
            return False
        return self._pattern.match(uri) is not None


def parse(text: str) -> tuple[list[IgnoreRule], list[str]]:
    """The rules parsed from ignorefile `text`, plus a message per malformed line."""
    rules: list[IgnoreRule] = []
    errors: list[str] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) != 3:
            errors.append(
                f"ignorefile line {number}: expected 3 fields (tool ruleId path), "
                f"got {len(fields)}"
            )
            continue
        tool, rule_id, path_glob = fields
        rules.append(IgnoreRule(tool, rule_id, path_glob))
    return rules, errors


def load(path: str) -> tuple[list[IgnoreRule], list[str]]:
    """The rules in the ignorefile at `path`, plus any read or parse error messages."""
    try:
        text = Path(path).read_text()
    except OSError as exc:
        return [], [f"could not read ignore file {path}: {exc}"]
    return parse(text)


def apply(artifact: Artifact, rules: list[IgnoreRule], target: str) -> int:
    """Drop ignored findings from `artifact` in place; return the number removed.

    Only SARIF findings can be ignored; a non-SARIF artifact (an SBOM) is untouched.
    `target` is the scan root, used to make a finding's path relative before matching.
    """
    if not rules or not isinstance(artifact, sarif.SarifDocument):
        return 0
    removed = 0
    for run in artifact.content.get("runs", []):
        driver = run.get("tool", {}).get("driver", {}).get("name", "")
        kept = []
        for result in run.get("results", []):
            if _is_ignored(result, driver, rules, target):
                removed += 1
            else:
                kept.append(result)
        run["results"] = kept
    return removed


def _is_ignored(
    result: dict[str, Any], driver: str, rules: list[IgnoreRule], target: str
) -> bool:
    rule_id = str(result.get("ruleId", ""))
    uri = _relative_uri(_result_uri(result), target)
    tools = _result_tools(result, driver)
    return any(rule.matches(rule_id, uri, tools) for rule in rules)


def _result_uri(result: dict[str, Any]) -> str:
    """The file uri of a SARIF result's first physical location, or ''."""
    for location in result.get("locations", []):
        uri = (
            location.get("physicalLocation", {}).get("artifactLocation", {}).get("uri")
        )
        if uri:
            return str(uri)
    return ""


def _result_tools(result: dict[str, Any], driver: str) -> list[str]:
    """The scanners that reported `result`: its merge annotation, or the run driver."""
    scanners = result.get("properties", {}).get("scanners")
    if isinstance(scanners, list) and scanners:
        return [str(scanner) for scanner in scanners]
    return [driver] if driver else []


def _relative_uri(uri: str, target: str) -> str:
    """`uri` made relative to the scan root `target`, for matching against a glob."""
    path = uri.removeprefix("file://")
    root = target.rstrip("/")
    if root and (path == root or path.startswith(root + "/")):
        path = path[len(root) :].lstrip("/")
    return path.removeprefix("./")


def _glob_to_regex(glob: str) -> re.Pattern[str]:
    """A gitignore-ish path glob compiled to an anchored regex.

    `**/` matches zero or more leading directories, `**` matches across directory
    separators, `*` matches within one path segment, and `?` matches one character.
    """
    out = ["^"]
    i = 0
    while i < len(glob):
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif glob.startswith("**", i):
            out.append(".*")
            i += 2
        elif glob[i] == "*":
            out.append("[^/]*")
            i += 1
        elif glob[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(glob[i]))
            i += 1
    out.append("$")
    return re.compile("".join(out))

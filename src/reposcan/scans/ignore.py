# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""reposcan ignorefile.

A repository may carry a `.reposcan-ignore` file whose entries suppress classes of
findings. Each non-blank, non-comment line has exactly three or four fields:

    <tool>  <ruleId>  <path-glob>  [content-regex]

`tool` is the scanner that reported the finding and `ruleId` is the SARIF rule id shown
in the finding; both are globs with alternation (`*` matches any run of characters, `?`
one, `|` separates alternatives), so `*` matches any and `poutine|zizmor` either. Every
other character is literal, so a dotted semgrep rule id matches as written. `path-glob`
is a repository-root-relative glob (`*` within a path segment, `**` across segments, `?`
one character).

Fields are whitespace-separated, and a `#` begins a comment. A field may be wrapped in
single or double quotes to include whitespace or a `#`; the quotes are removed.

The optional fourth field is a regular expression. When present, a finding is dropped
only if -- in addition to the tool, rule, and path matching -- the offending content
matches the regex. The offending content is the finding's line (or the whole file when
the finding has no line); if it cannot be read, the finding is kept. Quote the regex
(e.g. `"uses: creator/"`) when it contains spaces or a `#`.
"""

import logging
import re
from collections.abc import Sequence
from pathlib import Path

from reposcan.scans import sarif

logger = logging.getLogger(__name__)

# The ignorefile reposcan looks for in a scanned repository by default.
DEFAULT_IGNORE_FILE = ".reposcan-ignore"


class IgnoreRule:
    """One ignorefile entry: a tool, rule id, path glob, and optional content regex."""

    def __init__(
        self, tool: str, rule_id: str, path_glob: str, content_pattern: str = ""
    ) -> None:
        self.tool = tool
        self.rule_id = rule_id
        self.path_glob = path_glob
        self.content_pattern = content_pattern
        self._tool = _field_to_regex(tool)
        self._rule = _field_to_regex(rule_id)
        self._pattern = _glob_to_regex(path_glob)
        self._content = re.compile(content_pattern) if content_pattern else None

    def matches(self, finding: sarif.SarifResult, root: str = "") -> bool:
        """Whether this rule ignores `finding`.

        Checks the rule id, tool, and path; then, if the rule carries a content
        pattern, that it matches the finding's offending content (read from `root`).
        Content that cannot be read fails the match, so the finding is kept.
        """
        if self._rule.match(finding.rule_id) is None:
            return False
        if not any(self._tool.match(scanner) for scanner in finding.scanners):
            return False
        if self._pattern.match(finding.uri) is None:
            return False
        if self._content is None:
            return True
        content = _offending_content(root, finding)
        return content is not None and self._content.search(content) is not None


def parse(text: str) -> tuple[list[IgnoreRule], list[str]]:
    """The rules parsed from ignorefile `text`, plus a message per malformed line."""
    rules: list[IgnoreRule] = []
    errors: list[str] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        try:
            fields = _split_fields(raw)
        except ValueError as exc:
            errors.append(f"ignorefile line {number}: {exc}")
            continue
        if not fields:  # blank or comment-only line
            continue
        if len(fields) not in (3, 4):
            errors.append(
                f"ignorefile line {number}: expected 3 or 4 fields, got {len(fields)}"
            )
            continue
        try:
            rules.append(IgnoreRule(*fields))
        except re.error as exc:
            errors.append(f"ignorefile line {number}: {exc}")
    return rules, errors


def _split_fields(line: str) -> list[str]:
    """The whitespace-separated fields of `line`, honouring quotes and comments.

    A single- or double-quoted span keeps its whitespace and `#` and drops the quotes;
    an unquoted `#` starts a comment. Backslashes are literal (regexes keep them).
    Raises ValueError on an unterminated quote.
    """
    fields: list[str] = []
    current: list[str] = []
    in_field = False
    quote = ""
    for ch in line:
        if quote:
            if ch == quote:
                quote = ""
            else:
                current.append(ch)
        elif ch in "\"'":
            quote = ch
            in_field = True
        elif ch == "#":
            break  # the rest of the line is a comment
        elif ch.isspace():
            if in_field:
                fields.append("".join(current))
                current = []
                in_field = False
        else:
            current.append(ch)
            in_field = True
    if quote:
        raise ValueError("unterminated quote")
    if in_field:
        fields.append("".join(current))
    return fields


def load(path: str) -> tuple[list[IgnoreRule], list[str]]:
    """The rules in the ignorefile at `path`, plus any read or parse error messages."""
    try:
        text = Path(path).read_text()
    except OSError as exc:
        return [], [f"could not read ignore file {path}: {exc}"]
    return parse(text)


def apply(
    runs: Sequence[sarif.SarifRun], rules: list[IgnoreRule], root: str = ""
) -> int:
    """Drop ignored findings from each run in place; return the number removed.

    `root` is the repository root, used to read the offending content for rules that
    carry a content pattern (see the module docstring).
    """
    if not rules:
        return 0
    removed = 0
    for run in runs:
        kept = []
        for finding in run.results():
            if any(rule.matches(finding, root) for rule in rules):
                removed += 1
            else:
                kept.append(finding)
        run.set_results(kept)
    return removed


def _offending_content(root: str, finding: sarif.SarifResult) -> str | None:
    """The finding's offending content, or None when it cannot be read.

    The line the finding points to, or the whole file when it has no line.
    """
    if not finding.uri:
        return None
    try:
        text = (Path(root) / finding.uri).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if finding.line <= 0:
        return text
    lines = text.splitlines()
    if finding.line > len(lines):
        return None
    return lines[finding.line - 1]


def _field_to_regex(field: str) -> re.Pattern[str]:
    """A tool/ruleId glob (with `|` alternation) compiled to an anchored regex.

    `*` matches any run of characters, `?` matches one, and `|` separates alternatives;
    every other character is matched literally (so a dotted semgrep rule id matches as
    written). `*` alone therefore matches any value.
    """
    alternatives = []
    for alternative in field.split("|"):
        out = []
        for ch in alternative:
            if ch == "*":
                out.append(".*")
            elif ch == "?":
                out.append(".")
            else:
                out.append(re.escape(ch))
        alternatives.append("".join(out))
    return re.compile("^(?:" + "|".join(alternatives) + ")$")


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

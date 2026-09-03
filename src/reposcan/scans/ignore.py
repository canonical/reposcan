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
the finding has no line), read from the commit the finding names when it names one
rather than from the working tree; if it cannot be read, the finding is kept. Quote the
regex (e.g. `"uses: creator/"`) when it contains spaces or a `#`.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from reposcan.execution.context import ExecutionContext
from reposcan.scans import sarif

# The ignorefile reposcan looks for in a scanned repository by default.
DEFAULT_IGNORE_FILE = ".reposcan-ignore"


@dataclass
class IgnoreRule:
    """One ignorefile entry: a tool, rule id, path glob, and optional content regex."""

    tool: str
    rule_id: str
    path_glob: str
    content_pattern: str = ""

    tool_regex: re.Pattern[str] = field(init=False, repr=False)
    rule_regex: re.Pattern[str] = field(init=False, repr=False)
    path_regex: re.Pattern[str] = field(init=False, repr=False)
    # None for the three-field form, which ignores a finding outright.
    content_regex: re.Pattern[str] | None = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Compile the entry's patterns, raising re.error on a malformed one."""
        self.tool_regex = _field_to_regex(self.tool)
        self.rule_regex = _field_to_regex(self.rule_id)
        self.path_regex = _glob_to_regex(self.path_glob)
        self.content_regex = (
            re.compile(self.content_pattern) if self.content_pattern else None
        )


def parse(text: str) -> tuple[list[IgnoreRule], list[str]]:
    """Parse ignorefile `text` into rules."""
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
    """Split `line` into whitespace-separated fields, honouring quotes and comments.

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
    """Load the rules in the ignorefile at `path`, plus any error messages."""
    try:
        text = Path(path).read_text()
    except OSError as exc:
        return [], [f"could not read ignore file {path}: {exc}"]
    return parse(text)


def apply(
    runs: Sequence[sarif.SarifRun],
    rules: list[IgnoreRule],
    ctx: ExecutionContext | None = None,
    target: str = "",
) -> int:
    """Drop ignored findings from each run in place; return the number removed.

    A rule ignores a finding when its tool, rule id, and path all match. A rule
    carrying a content regex additionally requires the offending line to match it;
    that line is read from `target` through `ctx`. Content that cannot be read fails
    the match, so the finding is kept.
    """
    if not rules:
        return 0
    removed = 0
    for run in runs:
        kept: list[sarif.SarifResult] = []
        for finding in run.results():
            candidates = [
                rule
                for rule in rules
                if rule.rule_regex.match(finding.rule_id) is not None
                and any(rule.tool_regex.match(name) for name in finding.scanners)
                and rule.path_regex.match(finding.uri) is not None
            ]
            if not candidates:
                kept.append(finding)
                continue
            conditional = [
                rule for rule in candidates if rule.content_regex is not None
            ]
            if len(conditional) < len(candidates):
                removed += 1  # at least one rule ignores it outright
                continue
            # Every candidate tests the offending line, so read it once for all of
            # them rather than once per rule.
            line = _offending_line(ctx, target, finding)
            if line is not None and any(
                rule.content_regex is not None and rule.content_regex.search(line)
                for rule in conditional
            ):
                removed += 1
                continue
            kept.append(finding)
        run.set_results(kept)
    return removed


def _offending_line(
    ctx: ExecutionContext | None, target: str, finding: sarif.SarifResult
) -> str | None:
    """Read the finding's offending content.

    The line the finding points to, or the whole file when it has no line.
    """
    if ctx is None:
        return None
    text = sarif.read_source(ctx, target, finding)
    if text is None:
        return None
    if finding.line <= 0:
        return text
    lines = text.splitlines()
    if finding.line > len(lines):
        return None
    return lines[finding.line - 1]


def _field_to_regex(field: str) -> re.Pattern[str]:
    """Compile a tool/ruleId glob (with `|` alternation) to an anchored regex.

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
    """Compile a gitignore-ish path glob to an anchored regex.

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

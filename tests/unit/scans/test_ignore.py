# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the reposcan ignorefile (reposcan.scans.ignore)."""

from collections.abc import Mapping, Sequence
from typing import cast

from reposcan.execution.context import ExecutionContext
from reposcan.execution.process import ExecResult, Failure
from reposcan.scans import ignore, sarif


class _FileContext:
    """A context serving a fixed set of files to `cat`."""

    name = "fake"

    def __init__(self, files: dict[str, str]) -> None:
        self._files = files

    def start(self) -> Failure | None:
        return None

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        user: object | None = None,
        timeout: float | None = None,
        stream_stdout: bool = False,
        stream_stderr: bool = False,
    ) -> ExecResult | Failure:
        path = command[1]
        if path not in self._files:
            return ExecResult(1, "", f"cat: {path}: No such file or directory")
        return ExecResult(0, self._files[path], "")

    def stop(self) -> None:
        return None


def _ctx(files: dict[str, str]) -> ExecutionContext:
    return cast(ExecutionContext, _FileContext(files))


def _loc(uri: str, line: int = 0) -> dict:
    physical: dict = {"artifactLocation": {"uri": uri}}
    if line:
        physical["region"] = {"startLine": line}
    return {"physicalLocation": physical}


def _result(
    rule_id: str, uri: str, scanners: list[str] | None = None, line: int = 0
) -> dict:
    result = {"ruleId": rule_id, "locations": [_loc(uri, line)]}
    if scanners is not None:
        result["properties"] = {"scanners": scanners}
    return result


def _finding(
    rule_id: str, uri: str, scanners: list[str] | None = None, line: int = 0
) -> sarif.SarifResult:
    return sarif.SarifResult(_result(rule_id, uri, scanners or ["x"], line))


def _ignores(
    rule: ignore.IgnoreRule,
    rule_id: str,
    uri: str,
    scanners: list[str] | None = None,
    line: int = 0,
) -> bool:
    """Whether `rule` ignores such a finding, driven through the only entry point."""
    runs = _runs(_result(rule_id, uri, scanners or ["x"], line))
    return ignore.apply(runs, [rule]) == 1


def _runs(*results: dict) -> list[sarif.SarifRun]:
    return [
        sarif.SarifRun(
            {"tool": {"driver": {"name": "reposcan"}}, "results": list(results)}
        )
    ]


def test_parse_reads_entries_and_reports_malformed_lines() -> None:
    text = (
        "# a comment\n"
        "\n"
        "trufflehog SentryToken tools/locks/*.txt   # trailing reason\n"
        "* CKV_AWS_18 **/*.tf\n"
        'poutine unverified_creator .github/workflows/*.yml "uses: sketchy/"\n'
        "twofields only\n"
        "one two three four five\n"
        '* R **/*.py "(unclosed"\n'
        'secrets Rule *.env "oops\n'
    )
    rules, errors = ignore.parse(text)
    assert [(r.tool, r.rule_id, r.path_glob, r.content_pattern) for r in rules] == [
        ("trufflehog", "SentryToken", "tools/locks/*.txt", ""),
        ("*", "CKV_AWS_18", "**/*.tf", ""),
        # a quoted fourth field keeps its internal spaces (quotes removed)
        ("poutine", "unverified_creator", ".github/workflows/*.yml", "uses: sketchy/"),
    ]
    assert len(errors) == 4
    assert "line 6" in errors[0]  # too few fields (2)
    assert "line 7" in errors[1]  # too many fields (5)
    assert "line 8" in errors[2]  # bad regex (carries re's message)
    assert "line 9" in errors[3] and "quote" in errors[3]  # unterminated quote


def test_a_single_star_stays_within_a_path_segment() -> None:
    rule = ignore.IgnoreRule("*", "R", "tools/locks/*.txt")
    assert _ignores(rule, "R", "tools/locks/checkov.txt")  # a direct child
    # a single * does not cross a path separator
    assert not _ignores(rule, "R", "tools/locks/sub/deep.txt")
    assert not _ignores(rule, "R", "other/checkov.txt")


def test_double_star_crosses_segments_including_none() -> None:
    rule = ignore.IgnoreRule("*", "R", "**/*.tf")
    assert _ignores(rule, "R", "main.tf")  # zero leading directories
    assert _ignores(rule, "R", "a/b/c/main.tf")  # any depth
    assert not _ignores(rule, "R", "main.tfvars")


def test_tool_and_rule_fields_glob_and_alternate() -> None:
    # `*`/`?` wildcards in the rule id, and `|` alternation over the reporting tool.
    rule = ignore.IgnoreRule("poutine|zizmor", "CKV_AWS_*", "**/*.tf")
    assert _ignores(rule, "CKV_AWS_18", "a/main.tf", ["zizmor"])
    assert _ignores(rule, "CKV_AWS_20", "main.tf", ["poutine"])
    # the rule id is outside the CKV_AWS_* glob
    assert not _ignores(rule, "CKV_GCP_1", "main.tf", ["poutine"])
    # the reporting tool is not among the alternatives
    assert not _ignores(rule, "CKV_AWS_18", "main.tf", ["checkov"])


def test_field_special_characters_are_literal_not_regex() -> None:
    # a dotted semgrep-style rule id: the dots match literally, not "any character".
    rule = ignore.IgnoreRule("*", "python.lang.foo", "**/*.py")
    assert _ignores(rule, "python.lang.foo", "a.py", ["semgrep"])
    assert not _ignores(rule, "pythonXlangXfoo", "a.py", ["semgrep"])


def test_apply_drops_only_the_matching_findings() -> None:
    rules, errors = ignore.parse(
        "trufflehog SentryToken tools/locks/*.txt\n* CKV_AWS_18 **/*.tf\n"
    )
    assert errors == []
    runs = _runs(
        # dropped: tool, rule, and path all match
        _result("SentryToken", "tools/locks/checkov.txt", ["trufflehog"]),
        # kept: same rule and path, but a different tool
        _result("SentryToken", "tools/locks/other.txt", ["semgrep"]),
        # dropped: the `*` tool rule matches any scanner, at any depth
        _result("CKV_AWS_18", "infra/deep/main.tf", ["checkov"]),
        # kept: a rule that no entry ignores
        _result("CKV_AWS_20", "infra/main.tf", ["checkov"]),
    )
    removed = ignore.apply(runs, rules)
    assert removed == 2
    assert [r.rule_id for r in runs[0].results()] == ["SentryToken", "CKV_AWS_20"]


def test_content_pattern_drops_a_finding_only_when_the_offending_line_matches() -> None:
    ctx = _ctx(
        {
            "/scan/acme/.github/workflows/ci.yml": (
                "steps:\n"
                "  - uses: sketchy/action@v1\n"  # line 2
                "  - uses: actions/checkout@v4\n"  # line 3
            )
        }
    )
    rules, errors = ignore.parse(
        'poutine unverified_creator .github/workflows/*.yml "uses: sketchy/"\n'
    )
    assert errors == []
    runs = _runs(
        _result("unverified_creator", ".github/workflows/ci.yml", ["poutine"], 2),
        _result("unverified_creator", ".github/workflows/ci.yml", ["poutine"], 3),
    )
    removed = ignore.apply(runs, rules, ctx, "/scan/acme")
    assert removed == 1  # only the sketchy/ line; actions/checkout is kept
    assert [r.line for r in runs[0].results()] == [3]


def test_content_pattern_keeps_the_finding_when_the_content_cannot_be_read() -> None:
    # A content-pattern rule fails closed: if the offending content is unreadable
    # (here, a missing file), the finding is kept rather than silently suppressed.
    rules, errors = ignore.parse("* R *.yml anything\n")
    assert errors == []
    runs = _runs(_result("R", "missing.yml", ["x"], 3))
    assert ignore.apply(runs, rules, _ctx({}), "/scan/acme") == 0
    assert [r.rule_id for r in runs[0].results()] == ["R"]


def test_content_pattern_keeps_the_finding_when_there_is_no_context() -> None:
    # Without a session there is nothing to read the offending line from, so a
    # content rule cannot match and fails closed the same way.
    rules, errors = ignore.parse("* R *.yml anything\n")
    assert errors == []
    runs = _runs(_result("R", "ci.yml", ["x"], 1))
    assert ignore.apply(runs, rules) == 0

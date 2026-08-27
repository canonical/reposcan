# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the reposcan ignorefile (repo_scanner.scans.ignore)."""

import tempfile
from pathlib import Path

from repo_scanner.scans import ignore, sarif


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
    assert rule.matches(_finding("R", "tools/locks/checkov.txt"))  # a direct child
    # a single * does not cross a path separator
    assert not rule.matches(_finding("R", "tools/locks/sub/deep.txt"))
    assert not rule.matches(_finding("R", "other/checkov.txt"))


def test_double_star_crosses_segments_including_none() -> None:
    rule = ignore.IgnoreRule("*", "R", "**/*.tf")
    assert rule.matches(_finding("R", "main.tf"))  # zero leading directories
    assert rule.matches(_finding("R", "a/b/c/main.tf"))  # any depth
    assert not rule.matches(_finding("R", "main.tfvars"))


def test_tool_and_rule_fields_glob_and_alternate() -> None:
    # `*`/`?` wildcards in the rule id, and `|` alternation over the reporting tool.
    rule = ignore.IgnoreRule("poutine|zizmor", "CKV_AWS_*", "**/*.tf")
    assert rule.matches(_finding("CKV_AWS_18", "a/main.tf", ["zizmor"]))
    assert rule.matches(_finding("CKV_AWS_20", "main.tf", ["poutine"]))
    # the rule id is outside the CKV_AWS_* glob
    assert not rule.matches(_finding("CKV_GCP_1", "main.tf", ["poutine"]))
    # the reporting tool is not among the alternatives
    assert not rule.matches(_finding("CKV_AWS_18", "main.tf", ["checkov"]))


def test_field_special_characters_are_literal_not_regex() -> None:
    # a dotted semgrep-style rule id: the dots match literally, not "any character".
    rule = ignore.IgnoreRule("*", "python.lang.foo", "**/*.py")
    assert rule.matches(_finding("python.lang.foo", "a.py", ["semgrep"]))
    assert not rule.matches(_finding("pythonXlangXfoo", "a.py", ["semgrep"]))


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
    with tempfile.TemporaryDirectory() as root:
        workflows = Path(root) / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text(
            "steps:\n"
            "  - uses: sketchy/action@v1\n"  # line 2
            "  - uses: actions/checkout@v4\n"  # line 3
        )
        rules, errors = ignore.parse(
            'poutine unverified_creator .github/workflows/*.yml "uses: sketchy/"\n'
        )
        assert errors == []
        runs = _runs(
            _result("unverified_creator", ".github/workflows/ci.yml", ["poutine"], 2),
            _result("unverified_creator", ".github/workflows/ci.yml", ["poutine"], 3),
        )
        removed = ignore.apply(runs, rules, root)
        assert removed == 1  # only the sketchy/ line; actions/checkout is kept
        assert [r.line for r in runs[0].results()] == [3]


def test_content_pattern_keeps_the_finding_when_the_content_cannot_be_read() -> None:
    # A content-pattern rule fails closed: if the offending content is unreadable
    # (here, a missing file), the finding is kept rather than silently suppressed.
    with tempfile.TemporaryDirectory() as root:
        rules, errors = ignore.parse("* R *.yml anything\n")
        assert errors == []
        runs = _runs(_result("R", "missing.yml", ["x"], 3))
        assert ignore.apply(runs, rules, root) == 0
        assert [r.rule_id for r in runs[0].results()] == ["R"]

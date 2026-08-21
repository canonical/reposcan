# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the reposcan ignorefile (repo_scanner.scans.ignore)."""

from repo_scanner.scans import ignore, sarif


def _loc(uri: str) -> dict:
    return {"physicalLocation": {"artifactLocation": {"uri": uri}}}


def _result(rule_id: str, uri: str, scanners: list[str] | None = None) -> dict:
    result = {"ruleId": rule_id, "locations": [_loc(uri)]}
    if scanners is not None:
        result["properties"] = {"scanners": scanners}
    return result


def test_parse_reads_entries_and_reports_malformed_lines() -> None:
    text = (
        "# a comment\n"
        "\n"
        "trufflehog SentryToken tools/locks/*.txt   # trailing reason\n"
        "* CKV_AWS_18 **/*.tf\n"
        "too many fields here now\n"
        "twofields only\n"
    )
    rules, errors = ignore.parse(text)
    assert [(r.tool, r.rule_id, r.path_glob) for r in rules] == [
        ("trufflehog", "SentryToken", "tools/locks/*.txt"),
        ("*", "CKV_AWS_18", "**/*.tf"),
    ]
    assert len(errors) == 2  # the 5-field and 2-field lines
    assert "line 5" in errors[0] and "line 6" in errors[1]


def test_a_single_star_stays_within_a_path_segment() -> None:
    rule = ignore.IgnoreRule("*", "R", "tools/locks/*.txt")
    assert rule.matches("R", "tools/locks/checkov.txt", ["x"])  # a direct child
    assert not rule.matches(
        "R", "tools/locks/sub/deep.txt", ["x"]
    )  # * does not cross /
    assert not rule.matches("R", "other/checkov.txt", ["x"])


def test_double_star_crosses_segments_including_none() -> None:
    rule = ignore.IgnoreRule("*", "R", "**/*.tf")
    assert rule.matches("R", "main.tf", ["x"])  # zero leading directories
    assert rule.matches("R", "a/b/c/main.tf", ["x"])  # any depth
    assert not rule.matches("R", "main.tfvars", ["x"])


def test_apply_drops_only_the_matching_findings() -> None:
    rules, errors = ignore.parse(
        "trufflehog SentryToken tools/locks/*.txt\n* CKV_AWS_18 **/*.tf\n"
    )
    assert errors == []
    doc = sarif.SarifDocument(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "reposcan"}},
                    "results": [
                        # dropped: tool, rule, and path all match (uri under target)
                        _result(
                            "SentryToken",
                            "/scan/repo/tools/locks/checkov.txt",
                            ["trufflehog"],
                        ),
                        # kept: same rule and path, but a different tool
                        _result(
                            "SentryToken",
                            "/scan/repo/tools/locks/other.txt",
                            ["semgrep"],
                        ),
                        # dropped: the `*` tool rule matches any scanner, at any depth
                        _result(
                            "CKV_AWS_18", "/scan/repo/infra/deep/main.tf", ["checkov"]
                        ),
                        # kept: a rule that no entry ignores
                        _result("CKV_AWS_20", "/scan/repo/infra/main.tf", ["checkov"]),
                    ],
                }
            ],
        }
    )
    removed = ignore.apply(doc, rules, "/scan/repo")
    assert removed == 2
    assert [r["ruleId"] for r in doc.results()] == ["SentryToken", "CKV_AWS_20"]


def test_apply_uses_the_run_driver_when_a_result_has_no_scanner_property() -> None:
    # A single-tool scan (secrets) names the tool on the run driver, not per result.
    rules, _ = ignore.parse("trufflehog SentryToken tools/locks/*.txt\n")
    doc = sarif.SarifDocument.from_results(
        "trufflehog",
        "1.0",
        [
            sarif.SarifResult(
                "SentryToken", "hash near sentry", "tools/locks/checkov.txt", 5
            )
        ],
    )
    assert ignore.apply(doc, rules, "/scan/repo") == 1
    assert doc.count() == 0

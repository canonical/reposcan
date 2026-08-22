# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""SARIF tests.scans.sarif)."""

import json

from repo_scanner.scans import sarif


def test_build_creates_a_finding_normalized_at_construction() -> None:
    finding = sarif.SarifResult.build(
        "AWS",
        "leaked key",
        "/scan/repo/src/app.py",
        12,
        "trufflehog",
        "/scan/repo",
        level="error",
    )
    assert finding.rule_id == "AWS"
    assert finding.message == "leaked key"
    assert finding.uri == "src/app.py"  # relativized at creation
    assert finding.line == 12
    assert finding.location == "src/app.py:12"
    assert finding.level == "error"
    assert finding.scanners == ["trufflehog"]  # annotated at creation
    assert finding.key == ("AWS", "src/app.py", 12)


def test_from_results_assembles_already_normalized_findings() -> None:
    finding = sarif.SarifResult.build(
        "AWS", "k", "/scan/repo/src/app.py", 3, "trufflehog", "/scan/repo"
    )
    doc = sarif.SarifDocument.from_results("trufflehog", "1.0", [finding])
    (assembled,) = doc.results()
    assert assembled.uri == "src/app.py"  # already relative from build
    assert assembled.scanners == ["trufflehog"]
    assert doc.to_dict()["runs"][0]["tool"]["driver"]["name"] == "trufflehog"


def test_parse_normalizes_each_result_at_ingestion() -> None:
    text = json.dumps(
        {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "rules": [
                                {"id": "R", "defaultConfiguration": {"level": "error"}}
                            ]
                        }
                    },
                    "results": [
                        {
                            "ruleId": "R",
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "file:///scan/repo/x.py"
                                        },
                                        "region": {"startLine": 4},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ]
        }
    )
    doc = sarif.parse(text, "semgrep", "/scan/repo")
    assert doc is not None
    (finding,) = doc.results()
    assert finding.uri == "x.py"  # file:// scheme and target prefix stripped
    assert finding.scanners == ["semgrep"]  # scanner annotated on ingest
    assert finding.level == "error"  # inherited from the rule's configuration


def test_parse_relativizes_every_location_not_just_the_primary() -> None:
    def _loc(uri: str) -> dict:
        return {"physicalLocation": {"artifactLocation": {"uri": uri}}}

    text = json.dumps(
        {
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "R",
                            "level": "warning",
                            "locations": [
                                _loc("/scan/repo/a.py"),
                                _loc("/scan/repo/nested/b.py"),
                            ],
                        }
                    ]
                }
            ]
        }
    )
    doc = sarif.parse(text, "semgrep", "/scan/repo")
    assert doc is not None
    (result,) = doc.results()
    uris = [
        location["physicalLocation"]["artifactLocation"]["uri"]
        for location in result.result["locations"]  # raw dict: all locations, not [0]
    ]
    assert uris == ["a.py", "nested/b.py"]  # both locations relativized, not just [0]


def test_parse_returns_none_for_non_sarif_text() -> None:
    assert sarif.parse("not json", "semgrep", "/scan/repo") is None

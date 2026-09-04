# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the scan-type registry (reposcan.scans.registry)."""

import pytest

from reposcan.scans.registry import SCANS, parse_scan_names


def test_parse_scan_names_splits_dedups_strips_and_rejects() -> None:
    # The `scans` parameter's converter runs at parse time: split on commas, strip
    # whitespace, drop empties, dedup in order; reject unknown or empty input.
    assert parse_scan_names(" sast , sast, ,secrets ") == ["sast", "secrets"]
    for bad in (" , ", "sast,bogus"):
        with pytest.raises(ValueError):
            parse_scan_names(bad)


def test_parse_scan_names_all_expands_to_every_scan() -> None:
    # `all` expands to every scan type, deduping against any also named explicitly.
    assert parse_scan_names("all") == list(SCANS)
    rest = [name for name in SCANS if name != "sast"]
    assert parse_scan_names("sast,all") == ["sast", *rest]

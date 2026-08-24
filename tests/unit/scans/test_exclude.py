# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for git-ignored-path exclusion (repo_scanner.scans.exclude)."""

from collections.abc import Mapping, Sequence

from repo_scanner.execution.process import ExecResult, Failure
from repo_scanner.scans import cyclonedx, sarif
from repo_scanner.scans.exclude import IgnoredPaths


class _FakeContext:
    name = "fake"

    def __init__(self, result: ExecResult | Failure) -> None:
        self._result = result
        self.commands: list[list[str]] = []

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
        stdin: str | None = None,
    ) -> ExecResult | Failure:
        self.commands.append(list(command))
        return self._result

    def stop(self) -> None:
        return None


def test_from_context_splits_git_output_into_dirs_and_files() -> None:
    # git ls-files -z emits NUL-terminated entries; a wholly-ignored dir ends in "/".
    ctx = _FakeContext(ExecResult(0, ".venv/\0src/.cache/\0secret.env\0", ""))
    ignored = IgnoredPaths.from_context(ctx, "/scan/acme")
    assert ignored.dirs == (".venv", "src/.cache")
    assert ignored.files == ("secret.env",)
    assert ctx.commands[0][:2] == ["git", "ls-files"]  # read-only lookup, cwd is target


def test_from_context_is_empty_when_git_fails() -> None:
    # Not a git repo / git missing -> no exclusions, scan proceeds unfiltered.
    for result in (Failure(reason="no git"), ExecResult(128, "", "fatal")):
        assert IgnoredPaths.from_context(_FakeContext(result), "/x") == IgnoredPaths()


def test_contains_matches_ignored_files_and_directory_subtrees() -> None:
    ignored = IgnoredPaths(dirs=(".tox", "src/.cache"), files=("secret.env",))
    assert ignored.contains("secret.env")  # an ignored file
    assert ignored.contains(".tox")  # the ignored directory itself
    assert ignored.contains(".tox/a/b/action.yml")  # under an ignored directory
    assert ignored.contains("src/.cache/x")  # under a nested ignored directory
    assert not ignored.contains("src/app.py")  # a tracked file
    assert not ignored.contains(".toxic/x")  # a prefix that is not the .tox directory


def _sarif(*uris: str) -> sarif.SarifDocument:
    """A SARIF document with one result per uri (all reported by poutine)."""
    results = [
        {
            "ruleId": "R",
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
            "properties": {"scanners": ["poutine"]},
        }
        for uri in uris
    ]
    driver = {"tool": {"driver": {"name": "reposcan"}}, "results": results}
    return sarif.SarifDocument({"version": "2.1.0", "runs": [driver]})


def _uris(doc: sarif.SarifDocument) -> list[str]:
    return [r.uri for r in doc.results()]


def test_filter_findings_drops_findings_under_ignored_paths() -> None:
    # Uris are already repo-relative here: the artifact is relativized before this runs.
    ignored = IgnoredPaths(dirs=(".tox",), files=())
    doc = _sarif(
        ".tox/x/src/action.yml",  # under the ignored .tox tree
        ".tox/y/action.yml",  # also under it
        ".github/workflows/ci.yml",  # kept
    )
    assert ignored.filter_findings(doc) == 2
    assert _uris(doc) == [".github/workflows/ci.yml"]


def test_filter_findings_is_a_noop_for_no_ignores_or_a_non_sarif_artifact() -> None:
    doc = _sarif(".tox/x/a.yml")
    assert IgnoredPaths().filter_findings(doc) == 0  # nothing is ignored
    assert doc.count() == 1
    sbom = cyclonedx.CycloneDxDocument({"components": [{"name": "flask"}]})
    assert IgnoredPaths(dirs=(".tox",)).filter_findings(sbom) == 0

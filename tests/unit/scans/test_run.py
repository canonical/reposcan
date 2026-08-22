# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the scan driver (repo_scanner.scans.run.run_scan)."""

from collections.abc import Mapping, Sequence

from repo_scanner.execution.process import ExecResult, Failure
from repo_scanner.scans import sarif
from repo_scanner.scans.base import Scan
from repo_scanner.scans.model import Artifact, ArtifactKind, ToolInvocation
from repo_scanner.scans.run import run_scan


class _FakeContext:
    name = "fake"

    def __init__(self, result: ExecResult | Failure) -> None:
        self._result = result
        self.commands: list[list[str]] = []
        self.streamed: list[tuple[bool, bool]] = []
        self.cwds: list[str | None] = []
        self.envs: list[Mapping[str, str] | None] = []

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
        self.streamed.append((stream_stdout, stream_stderr))
        self.cwds.append(cwd)
        self.envs.append(env)
        return self._result

    def stop(self) -> None:
        return None


class _FakeScan(Scan):
    # Invokes one real registered tool so installed-path lookup resolves.
    name = "faux"

    def invocations(self, target: str) -> list[ToolInvocation]:
        return [ToolInvocation("trufflehog", ["--version"])]

    def parse(self, tool: str, output: ExecResult, target: str) -> Artifact | Failure:
        return sarif.SarifDocument({"runs": [{"results": []}]})

    def consolidate(self, artifacts: Sequence[Artifact]) -> Artifact | Failure:
        return sarif.SarifDocument({"runs": [{"results": []}]})


class _Scan(Scan):
    # A scan running the given invocations; records each ExecResult it parses.
    name = "faux"

    def __init__(self, invocations: list[ToolInvocation]) -> None:
        super().__init__()
        self._invocations = invocations
        self.seen: list[ExecResult] = []

    def invocations(self, target: str) -> list[ToolInvocation]:
        return self._invocations

    def parse(self, tool: str, output: ExecResult, target: str) -> Artifact | Failure:
        self.seen.append(output)
        return sarif.SarifDocument({"runs": [{"results": []}]})

    def consolidate(self, artifacts: Sequence[Artifact]) -> Artifact | Failure:
        return sarif.SarifDocument({"runs": [{"results": []}]})


def test_run_scan_runs_each_tool_at_its_installed_path_and_consolidates() -> None:
    ctx = _FakeContext(ExecResult(0, "", ""))
    artifact = run_scan(_FakeScan(), ctx, "/scan/acme", "/opt/reposcan")
    assert not isinstance(artifact, Failure)
    assert artifact.kind is ArtifactKind.SARIF
    assert ctx.commands[0][:2] == ["git", "ls-files"]  # the git-ignored-path lookup
    assert ctx.commands[1][0] == "/opt/reposcan/bin/trufflehog"


def test_run_scan_reports_a_nonzero_tool_exit_as_a_failure() -> None:
    ctx = _FakeContext(ExecResult(2, "", "trufflehog: bad target"))
    result = run_scan(_FakeScan(), ctx, "/scan/acme", "/opt/reposcan")
    assert isinstance(result, Failure)
    assert "trufflehog failed" in result.reason


def test_run_scan_streams_tool_progress_but_not_its_stdout() -> None:
    ctx = _FakeContext(ExecResult(0, "", ""))
    run_scan(_FakeScan(), ctx, "/scan/acme", "/opt/reposcan", stream=True)
    # The git ls-files lookup streams nothing; the tool's stderr (progress) streams
    # while its stdout (results) is captured but not echoed.
    assert ctx.streamed == [(False, False), (False, True)]


def test_run_scan_cwd_and_exclusions_per_invocation() -> None:
    # A filesystem tool triggers a git ls-files; git runs at the target, tools run at
    # their cwd (the target); an invocation may pin its cwd.
    ctx = _FakeContext(ExecResult(0, ".venv/\0secret.env\0", ""))
    scan = _Scan(
        [
            ToolInvocation("trivy", ["fs", "/scan/acme"]),
            ToolInvocation("govulncheck", ["-version"], cwd="/module"),
        ]
    )
    run_scan(scan, ctx, "/scan/acme", "/opt/reposcan")
    assert ctx.commands[0][:2] == ["git", "ls-files"]
    assert ctx.cwds == ["/scan/acme", "/scan/acme", "/module"]
    assert ctx.commands[1][3:] == ["--skip-dirs", ".venv", "--skip-files", "secret.env"]


def test_run_scan_records_tool_invocations_as_provenance() -> None:
    # The consolidated report carries each executed command; env is only what the
    # invocation set (never the inherited process environment).
    ctx = _FakeContext(ExecResult(0, "", ""))
    scan = _Scan([ToolInvocation("trufflehog", ["--version"], env={"K": "V"})])
    artifact = run_scan(scan, ctx, "/scan/acme", "/opt/reposcan")
    assert not isinstance(artifact, Failure)
    (invocation,) = artifact.to_dict()["runs"][0]["invocations"]
    assert invocation["commandLine"] == "/opt/reposcan/bin/trufflehog --version"
    assert invocation["environmentVariables"] == {"K": "V"}
    assert invocation["exitCode"] == 0 and invocation["executionSuccessful"] is True
    assert invocation["properties"]["tool"] == "trufflehog"


def test_run_scan_reads_output_file_and_passes_env() -> None:
    # An output_file makes run_scan use the file's content (read via cat), and the
    # invocation's env reaches the tool.
    ctx = _FakeContext(ExecResult(0, "FILE-BOM", ""))
    inv = ToolInvocation(
        "checkov", ["-d", "x"], env={"K": "V"}, output_file="/out.json"
    )
    scan = _Scan([inv])
    run_scan(scan, ctx, "/scan/acme", "/opt/reposcan")
    assert scan.seen[0].stdout == "FILE-BOM"
    assert {"K": "V"} in ctx.envs and ["cat", "/out.json"] in ctx.commands

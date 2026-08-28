# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the tool install model (reposcan.tools).

The value here is the install-command generation for each install shape and the
dependency-ordered install plan; the plain data on the dataclasses (kind, requires)
is exercised through the registry and the plan, not asserted field-by-field.
"""

from reposcan.tools.install import install_plan
from reposcan.tools.model import (
    Download,
    GoTool,
    NativeBinary,
    Platform,
    PypiTool,
)

_LINUX = Platform("linux", "amd64")
_ROOT = "/opt/tools"

# Prerequisites first, so the dependent tools below can name them in `requires`.
_GO_SDK = NativeBinary(
    name="go",
    version="1.26.4",
    downloads=(Download("linux", "amd64", "https://example/go.tar.gz", "go-hash"),),
)
_UV = NativeBinary(
    name="uv",
    version="0.11.25",
    downloads=(Download("linux", "amd64", "https://example/uv.tar.gz", "uv-hash"),),
)
_TRUFFLEHOG = NativeBinary(
    name="trufflehog",
    version="3.95.6",
    downloads=(
        Download("linux", "amd64", "https://example/trufflehog.tar.gz", "abc123"),
    ),
)
_CDXGEN = NativeBinary(  # a bare (unarchived) binary: URL is not a tarball
    name="cdxgen",
    version="12.7.0",
    downloads=(Download("linux", "amd64", "https://example/cdxgen-linux-amd64", "d"),),
)
_SEMGREP = PypiTool(
    name="semgrep",
    version="1.168.0",
    requirements="semgrep==1.168.0 --hash=sha256:deadbeef",
    entrypoints=("semgrep",),
    requires=(_UV,),
)
_GOVULNCHECK = GoTool(
    name="govulncheck",
    version="1.5.0",
    module="golang.org/x/vuln",
    module_sum="h1:modhash=",
    gomod_sum="h1:gomodhash=",
    package="golang.org/x/vuln/cmd/govulncheck",
    requires=(_GO_SDK,),
)


def test_native_binary_tarball_extracts_finds_and_symlinks() -> None:
    lines = "\n".join(_TRUFFLEHOG.install_commands(_LINUX, _ROOT))
    assert "https://example/trufflehog.tar.gz" in lines
    assert "abc123" in lines  # sha256 verification
    # Extracted whole under opt/, the executable found by name (it may be nested),
    # and symlinked into bin/.
    assert "tar -xf" in lines and "/opt/tools/opt/trufflehog" in lines
    assert "find" in lines and '-name "trufflehog"' in lines
    assert "ln -sf" in lines and "/opt/tools/bin/trufflehog" in lines
    # No build for the target platform fails loudly rather than installing nothing.
    missing = _TRUFFLEHOG.install_commands(Platform("linux", "arm64"), _ROOT)
    assert any("exit 1" in line for line in missing)


def test_bare_binary_installs_directly_without_extraction() -> None:
    lines = "\n".join(_CDXGEN.install_commands(_LINUX, _ROOT))
    assert "tar -xf" not in lines  # nothing to extract
    assert "install -m 0755" in lines and "/opt/tools/bin/cdxgen" in lines


def test_multi_file_download_is_kept_whole_and_symlinked() -> None:
    # A multi-file download (the Go toolchain) is extracted whole and its executable
    # symlinked into bin/, never copied out as a lone binary (which would strand it
    # from its siblings).
    lines = "\n".join(_GO_SDK.install_commands(_LINUX, _ROOT))
    assert "tar -xf" in lines and "/opt/tools/opt/go" in lines
    assert "ln -sf" in lines and "/opt/tools/bin/go" in lines
    assert "install -m 0755" not in lines


def test_pypi_writes_the_hash_lock_inline_then_installs_from_it() -> None:
    lines = "\n".join(_SEMGREP.install_commands(_LINUX, _ROOT))
    assert "--hash=sha256:deadbeef" in lines  # lock contents written inline
    assert "--require-hashes" in lines
    assert "/opt/tools/pypi/semgrep.txt" in lines  # written, then installed from
    assert "/opt/tools/bin/uv" in lines  # the uv we installed, not a PATH uv


def test_go_tool_pins_the_module_and_builds_with_the_sdk_go() -> None:
    lines = "\n".join(_GOVULNCHECK.install_commands(_LINUX, _ROOT))
    assert "h1:modhash=" in lines  # the stored go.sum hash
    assert "GOSUMDB=off" in lines  # verified against our pin, not sum.golang.org
    assert "golang.org/x/vuln/cmd/govulncheck@v1.5.0" in lines
    assert "/opt/tools/bin/go" in lines  # the go binary from the SDK it requires


def test_installed_path_is_the_executable_the_symlink_points_to() -> None:
    # bin/<name> for binaries and Go tools; bin/<entrypoint> for a PyPI tool.
    assert _GO_SDK.installed_path(_ROOT) == "/opt/tools/bin/go"
    assert _GOVULNCHECK.installed_path(_ROOT) == "/opt/tools/bin/govulncheck"
    assert _SEMGREP.installed_path(_ROOT) == "/opt/tools/bin/semgrep"  # entrypoint


def test_install_plan_pulls_in_prerequisites_ordered_and_deduped() -> None:
    # Request the dependents plus one explicit prerequisite; install_plan pulls in the
    # missing prerequisites, de-dupes, and orders each tool after what it requires.
    plan = install_plan([_SEMGREP, _GOVULNCHECK, _UV], _LINUX, _ROOT)
    names = [step.tool.name for step in plan]
    assert set(names) == {"uv", "semgrep", "go", "govulncheck"}  # go pulled in
    assert names.count("uv") == 1  # requested and required by semgrep, listed once
    assert names.index("go") < names.index("govulncheck")  # Go SDK before Go tools
    assert names.index("uv") < names.index("semgrep")  # uv before PyPI tools

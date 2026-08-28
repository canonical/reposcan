# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The tool registry: every tool reposcan drives, defined once with its pins.

This is the single source of truth the plan calls for. Each entry names a tool and
carries its supply-chain pins inline, so versions, download URLs, and hashes are all
auditable here rather than in a separate manifest. The pins were transcribed from the
tools' official published checksums (GitHub release checksum files, go.dev/dl, the Go
checksum database, and `uv pip compile --generate-hashes` for the PyPI locks).

Each tool carries a `# verify:` comment linking a page where its pinned version and
sha256 can be independently checked without trusting this file: go.dev/dl, the
pypi.org file listings, and the Go checksum database show the hash on the page
itself; for the GitHub-released binaries the linked release page carries the
project's own published checksums for that version.

`TOOLS` is a map of display-name:Tool pairs for all user-facing scanning tools.
"""

from pathlib import Path

from reposcan.tools.model import (
    Download,
    GoTool,
    NativeBinary,
    PypiTool,
    Tool,
)

_LOCKS = Path(__file__).parent / "locks"


def _lock(name: str) -> str:
    """The contents of a generated PyPI hash-lock, shipped beside this module."""
    return (_LOCKS / f"{name}.txt").read_text()


def _gh(repo: str, tag: str, asset: str) -> str:
    """A GitHub release download URL.

    Spelled from its parts because the full URLs run past the line limit and
    repo/tag/asset are the parts that actually vary.
    """
    return f"https://github.com/{repo}/releases/download/{tag}/{asset}"


# --- Prerequisites: not scanning tools and not listed in TOOLS, these are named in
# --- the scanning tools' `requires` and pulled in when those tools are installed. ---

# uv is an ordinary native binary; every PyPI tool names it in `requires`.
# verify: https://github.com/astral-sh/uv/releases/tag/0.11.26
UV = NativeBinary(
    name="uv",
    version="0.11.26",
    downloads=(
        Download(
            os="linux",
            arch="amd64",
            url=_gh("astral-sh/uv", "0.11.26", "uv-x86_64-unknown-linux-gnu.tar.gz"),
            sha256="6426a73c3837e6e2483ee344cbc00f36394d179afcba6183cb77437e67db4af0",
        ),
        Download(
            os="linux",
            arch="arm64",
            url=_gh("astral-sh/uv", "0.11.26", "uv-aarch64-unknown-linux-gnu.tar.gz"),
            sha256="befa1a59c91e96eb601b0fd9a97c03dd666f17baba644b2b4db9c59a767e387e",
        ),
    ),
)

# Subdirectory of the install root where uv keeps its managed Python interpreters
# (via UV_PYTHON_INSTALL_DIR). Kept under the install root for unified perms mgmt.
UV_PYTHON_SUBDIR = "python"

# The Go toolchain: an ordinary native binary. Its download is a multi-file tree, so
# it is kept whole and its `go` executable is symlinked to bin/go (which still finds
# GOROOT). Go tools name it in `requires`.
# verify: https://go.dev/dl/#go1.26.4  (SHA256 shown in the table)
GO_SDK = NativeBinary(
    name="go",
    version="1.26.4",
    downloads=(
        Download(
            os="linux",
            arch="amd64",
            url="https://go.dev/dl/go1.26.4.linux-amd64.tar.gz",
            sha256="1153d3d50e0ac764b447adfe05c2bcf08e889d42a02e0fe0259bd47f6733ad7f",
        ),
        Download(
            os="linux",
            arch="arm64",
            url="https://go.dev/dl/go1.26.4.linux-arm64.tar.gz",
            sha256="ef758ae7c6cf9267c9c0ef080b8965f453d89ab2d25d9eb22de4405925238768",
        ),
    ),
)

# --- Native binaries. --------------------------------------------------------------

# verify: https://github.com/trufflesecurity/trufflehog/releases/tag/v3.95.8
TRUFFLEHOG = NativeBinary(
    name="trufflehog",
    version="3.95.8",
    downloads=(
        Download(
            os="linux",
            arch="amd64",
            url=_gh(
                "trufflesecurity/trufflehog",
                "v3.95.8",
                "trufflehog_3.95.8_linux_amd64.tar.gz",
            ),
            sha256="136c42933697ab2e09402d003ff4259086312b80cb671e7d9ab05477597bc4f0",
        ),
        Download(
            os="linux",
            arch="arm64",
            url=_gh(
                "trufflesecurity/trufflehog",
                "v3.95.8",
                "trufflehog_3.95.8_linux_arm64.tar.gz",
            ),
            sha256="49231b33cdd49dee4e98c7efc9acfb16e8d08ac5fed84bf7e983656487a96b98",
        ),
    ),
)

# verify: https://github.com/anchore/syft/releases/tag/v1.46.0
SYFT = NativeBinary(
    name="syft",
    version="1.46.0",
    downloads=(
        Download(
            os="linux",
            arch="amd64",
            url=_gh("anchore/syft", "v1.46.0", "syft_1.46.0_linux_amd64.tar.gz"),
            sha256="d654f678b709eb53c393d38519d5ed7d2e57205529404018614cfefa0fb2b5ca",
        ),
        Download(
            os="linux",
            arch="arm64",
            url=_gh("anchore/syft", "v1.46.0", "syft_1.46.0_linux_arm64.tar.gz"),
            sha256="9fafef4db4f032ce81008d3a1529985d41ceb6ccdf2b388c9ce2f1ed7d32082e",
        ),
    ),
)

# verify: https://github.com/anchore/grype/releases/tag/v0.115.0
GRYPE = NativeBinary(
    name="grype",
    version="0.115.0",
    downloads=(
        Download(
            os="linux",
            arch="amd64",
            url=_gh("anchore/grype", "v0.115.0", "grype_0.115.0_linux_amd64.tar.gz"),
            sha256="3fad92940650e514c0aa2dad83526942a055e210cec09a8a59d9c024adc2b90e",
        ),
        Download(
            os="linux",
            arch="arm64",
            url=_gh("anchore/grype", "v0.115.0", "grype_0.115.0_linux_arm64.tar.gz"),
            sha256="b8541b9ecc3e936e7db4ff14b71a9474b25f3898ccaad63ee0bfe3449fcd734d",
        ),
    ),
)

# verify: https://github.com/aquasecurity/trivy/releases/tag/v0.72.0
TRIVY = NativeBinary(
    name="trivy",
    version="0.72.0",
    downloads=(
        Download(
            os="linux",
            arch="amd64",
            url=_gh("aquasecurity/trivy", "v0.72.0", "trivy_0.72.0_Linux-64bit.tar.gz"),
            sha256="bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea",
        ),
        Download(
            os="linux",
            arch="arm64",
            url=_gh("aquasecurity/trivy", "v0.72.0", "trivy_0.72.0_Linux-ARM64.tar.gz"),
            sha256="2ca2c023109c2db6b2b77366b6717291452d4531167377d95c79547f0c8e3467",
        ),
    ),
)

# verify: https://github.com/boostsecurityio/poutine/releases/tag/v1.1.6
POUTINE = NativeBinary(
    name="poutine",
    version="1.1.6",
    downloads=(
        Download(
            os="linux",
            arch="amd64",
            url=_gh("boostsecurityio/poutine", "v1.1.6", "poutine_Linux_x86_64.tar.gz"),
            sha256="abde716599a65608b023a69ed9316e5f083a7bca48612151c2720835883757ea",
        ),
        Download(
            os="linux",
            arch="arm64",
            url=_gh("boostsecurityio/poutine", "v1.1.6", "poutine_Linux_arm64.tar.gz"),
            sha256="460c90300c6329106b551c150682d12e457365f6436a6cbbd08fe79eb9a98131",
        ),
    ),
)

# cdxgen ships a bare (unarchived) binary; NativeBinary installs it directly.
# verify: https://github.com/CycloneDX/cdxgen/releases/tag/v12.7.0
CDXGEN = NativeBinary(
    name="cdxgen",
    version="12.7.0",
    downloads=(
        Download(
            os="linux",
            arch="amd64",
            url=_gh("CycloneDX/cdxgen", "v12.7.0", "cdxgen-linux-amd64"),
            sha256="e202de54d1a99e388eddf9b21bf11b3301f8495a77e84a5d323f9b867160d731",
        ),
        Download(
            os="linux",
            arch="arm64",
            url=_gh("CycloneDX/cdxgen", "v12.7.0", "cdxgen-linux-arm64"),
            sha256="b9df01473f0cd28a1911b276feb81a8ed410c947eb84266b59333513ec8afdc5",
        ),
    ),
)

# --- Go tools: built with the pinned Go SDK, verified against the checksum DB. ------

# verify: https://sum.golang.org/lookup/golang.org/x/vuln@v1.5.0  (the h1: go.sum lines)
GOVULNCHECK = GoTool(
    name="govulncheck",
    version="1.5.0",
    module="golang.org/x/vuln",
    package="golang.org/x/vuln/cmd/govulncheck",
    module_sum="h1:jGVVuNZ7NrBJlFB7IBkZ/R9c8gYCja+SWqrHpBCYJZA=",
    gomod_sum="h1:Ujq+7kg+6B5HsCgDFbMmP0+gAV1zGf05mkh4uF5YEXY=",
    requires=(GO_SDK,),
)

# --- PyPI tools: installed into isolated venvs from hash-pinned locks. --------------

# verify: https://pypi.org/project/semgrep/1.168.0/#files  (per-file SHA256)
SEMGREP = PypiTool(
    name="semgrep",
    version="1.168.0",
    requirements=_lock("semgrep"),
    entrypoints=("semgrep",),
    requires=(UV,),
)

# verify: https://pypi.org/project/checkov/3.3.6/#files  (per-file SHA256)
CHECKOV = PypiTool(
    name="checkov",
    version="3.3.6",
    requirements=_lock("checkov"),
    entrypoints=("checkov",),
    requires=(UV,),
)

# verify: https://pypi.org/project/zizmor/1.26.1/#files  (per-file SHA256)
ZIZMOR = PypiTool(
    name="zizmor",
    version="1.26.1",
    requirements=_lock("zizmor"),
    entrypoints=("zizmor",),
    requires=(UV,),
)

# all user-facing scanning tools keyed by name
TOOLS: dict[str, Tool] = {
    tool.name: tool
    for tool in (
        SEMGREP,
        CHECKOV,
        ZIZMOR,
        TRUFFLEHOG,
        SYFT,
        GRYPE,
        TRIVY,
        POUTINE,
        CDXGEN,
        GOVULNCHECK,
    )
}

# --- Resolvers
# used to generate lockfiles. Not surfaced in user-facing tool lists.

# verify: https://pypi.org/project/poetry/2.4.1/#files  (per-file SHA256)
# poetry-plugin-export (bundled in the lock) restores `poetry export`, which poetry
# dropped from its core in 2.0.
POETRY = PypiTool(
    name="poetry",
    version="2.4.1",
    requirements=_lock("poetry"),
    entrypoints=("poetry",),
    requires=(UV,),
)

# verify: https://pypi.org/project/pipenv/2026.7.1/#files  (per-file SHA256)
PIPENV = PypiTool(
    name="pipenv",
    version="2026.7.1",
    requirements=_lock("pipenv"),
    entrypoints=("pipenv",),
    requires=(UV,),
)

# Node LTS ("Krypton"). Its bundled npm resolves package.json repos (npm/yarn/bun all
# keep their deps there); `also_link` exposes that npm at bin/npm beside bin/node.
# verify: https://nodejs.org/dist/v24.19.0/SHASUMS256.txt  (per-file SHA256)
NODE = NativeBinary(
    name="node",
    version="24.19.0",
    executable="node",
    also_link=("npm",),
    downloads=(
        Download(
            os="linux",
            arch="amd64",
            url="https://nodejs.org/dist/v24.19.0/node-v24.19.0-linux-x64.tar.gz",
            sha256="f625d97cd707df4ff96254916fbc5ff014f09c09effe5a1e0ca8f6d41a8789d4",
        ),
        Download(
            os="linux",
            arch="arm64",
            url="https://nodejs.org/dist/v24.19.0/node-v24.19.0-linux-arm64.tar.gz",
            sha256="d28c8a5bf0a808f0ed434a1dce8c54ae98f0371c0bd86ac58abc613f73e6643f",
        ),
    ),
)

# pnpm ships self-contained (a bundled Node), so it needs no Node install of its own.
# verify: https://github.com/pnpm/pnpm/releases/tag/v11.21.0
PNPM = NativeBinary(
    name="pnpm",
    version="11.21.0",
    downloads=(
        Download(
            os="linux",
            arch="amd64",
            url=_gh("pnpm/pnpm", "v11.21.0", "pnpm-linux-x64.tar.gz"),
            sha256="aadc489ce4473c2af0fec06a5c19e113b5793d404eac49853c8153bf4b0d8263",
        ),
        Download(
            os="linux",
            arch="arm64",
            url=_gh("pnpm/pnpm", "v11.21.0", "pnpm-linux-arm64.tar.gz"),
            sha256="64eb219b008f7a4c176d81fbce919c20b0b7e093e815cbb669d46e681451f43b",
        ),
    ),
)

RESOLVER_TOOLS: tuple[Tool, ...] = (POETRY, PIPENV, NODE, PNPM)

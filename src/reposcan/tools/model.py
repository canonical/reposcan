# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The Tool model: reposcan's external tools, defined in code.

Every tool is one of a few kinds: a PyPI package, a prebuilt native binary
(including the pinned Go toolchain, which is kept as a whole tree), or a Go module
built with `go install`. A tool carries its own supply-chain pins so the whole set
of tools and their pins is auditable in one place rather than split across a
separate manifest:

  - native binaries (including the Go SDK) pin each per-platform download by sha256;
  - Go tools pin the module by its go.sum h1 hashes, verified at build;
  - PyPI tools install from a hash-pinned requirements lock (--require-hashes).

Each tool also knows how to install itself: `install_commands(platform, install_root)`
returns the shell lines that install it, for a platform, under an install root. Those
lines are the single definition that both `reposcan bootstrap` (run through an
execution context) and image generation (a build script) consume; see
tools/install.py.
"""

from dataclasses import dataclass
from enum import Enum
from typing import ClassVar, Protocol


class ToolKind(str, Enum):
    """How a tool is installed: from PyPI, a prebuilt download, or Go source.

    The prebuilt download may be a native binary or the Go SDK archive. Used for
    display; the actual install behavior comes from the tool's type, not this label.
    """

    PYPI = "pypi"
    NATIVE_BINARY = "native_binary"
    GO = "go"


@dataclass(frozen=True)
class Download:
    """A downloadable artifact for one OS/arch, pinned by sha256."""

    os: str
    arch: str
    url: str
    sha256: str


@dataclass(frozen=True)
class Platform:
    """An OS/arch that tools are installed for."""

    os: str  # e.g. "linux"
    arch: str  # e.g. "amd64"


# Shell command that visibly fails the install when a tool has no build for the target
_NO_DOWNLOAD = "echo 'no {name} {version} build for {os}/{arch}' >&2; exit 1"


class Tool(Protocol):
    """Common identity and install behavior of every tool, whatever its kind."""

    kind: ClassVar[ToolKind]

    @property
    def requires(self) -> "tuple[Tool, ...]":
        """The tools that must be installed before this one (its dependencies).

        PyPI tools require uv, Go tools require the Go SDK; empty when there is none.
        """
        ...

    @property
    def name(self) -> str: ...

    @property
    def version(self) -> str: ...

    def install_commands(self, platform: Platform, install_root: str) -> list[str]:
        """Shell lines that install this tool, for `platform`, under `install_root`.

        Each line is run via the execution context (bootstrap) or concatenated into
        an image build script (image generation).
        """
        ...

    def installed_path(self, install_root: str) -> str:
        """The installed executable's path under `install_root`.

        It exists only once the tool is installed, so it doubles as an install marker.
        """
        ...


@dataclass(frozen=True, kw_only=True)
class NativeBinary:
    """A tool installed from a pinned per-platform prebuilt download.

    `executable` is the executable's name inside the download (defaulting to `name`);
    it is exposed at `bin/<name>`, whatever shape the download takes:

    - an archive is extracted whole under `opt/<name>/`, and the executable, found
      wherever it sits, is symlinked into `bin/`. Keeping the tree lets multi-file
      downloads like the Go toolchain resolve their siblings (its `go` binary finds
      GOROOT through the symlink); single-file archives just symlink one binary.
    - a bare (unarchived) binary is installed straight to `bin/<name>`.

    `also_link` names extra sibling executables in the tree's `bin/` to expose at
    `bin/<name>` too (e.g. Node's bundled `npm` alongside `node`).
    """

    name: str
    version: str
    executable: str = ""
    also_link: tuple[str, ...] = ()
    requires: tuple[Tool, ...] = ()
    downloads: tuple[Download, ...] = ()
    kind: ClassVar[ToolKind] = ToolKind.NATIVE_BINARY

    def _download_for(self, platform: Platform) -> Download | None:
        for download in self.downloads:
            if download.os == platform.os and download.arch == platform.arch:
                return download
        return None

    def _fetch(self, download: Download, archive: str) -> list[str]:
        """Download `download` to `archive` and verify its sha256."""
        return [
            f'curl -fsSL "{download.url}" -o "{archive}"',
            f'echo "{download.sha256}  {archive}" | sha256sum -c -',
        ]

    def installed_path(self, install_root: str) -> str:
        return f"{install_root}/bin/{self.name}"

    def install_commands(self, platform: Platform, install_root: str) -> list[str]:
        download = self._download_for(platform)
        if download is None:
            return [
                _NO_DOWNLOAD.format(
                    name=self.name,
                    version=self.version,
                    os=platform.os,
                    arch=platform.arch,
                )
            ]
        cache = f"{install_root}/cache"
        archive = f"{cache}/{self.name}-{self.version}"
        dest = f"{install_root}/bin/{self.name}"
        executable = self.executable or self.name
        commands = [
            f'mkdir -p "{cache}" "{install_root}/bin"',
            *self._fetch(download, archive),
        ]
        if download.url.endswith((".tar.gz", ".tgz", ".tar")):
            # Extract the archive whole and symlink the executable (found wherever it
            # sits, so platform-nested layouts need no special-casing) into bin/.
            tree = f"{install_root}/opt/{self.name}"
            commands += [
                f'rm -rf "{tree}" && mkdir -p "{tree}"',
                f'tar -xf "{archive}" -C "{tree}"',
                f'ln -sf "$(find "{tree}" -type f -name "{executable}" | head -1)" '
                f'"{dest}"',
            ]
            # Expose extra sibling executables (e.g. Node's `npm`) from the tree's bin/.
            commands += [
                f'ln -sf "$(find "{tree}" -path "*/bin/{extra}" | head -1)" '
                f'"{install_root}/bin/{extra}"'
                for extra in self.also_link
            ]
        else:
            # A bare binary download: install it directly.
            commands.append(f'install -m 0755 "{archive}" "{dest}"')
        return commands


@dataclass(frozen=True)
class PypiTool:
    """A tool distributed on PyPI, installed into an isolated venv from a pinned lock.

    The lock is hash-pinned. `requirements` is the lock's contents (a --generate-hashes
    file); install writes it into place first, like the Go go.sum, so nothing needs
    to pre-exist in the container. `entrypoints` are the console scripts it provides,
    linked onto the tool bin dir.
    """

    name: str
    version: str
    requirements: str
    entrypoints: tuple[str, ...] = ()
    requires: tuple[Tool, ...] = ()
    kind: ClassVar[ToolKind] = ToolKind.PYPI

    def installed_path(self, install_root: str) -> str:
        # path to invoke the package's first console script.
        entry = self.entrypoints[0] if self.entrypoints else self.name
        return f"{install_root}/bin/{entry}"

    def install_commands(self, platform: Platform, install_root: str) -> list[str]:
        uv = f"{install_root}/bin/uv"  # the uv binary, installed first
        pypi = f"{install_root}/pypi"
        venv = f"{pypi}/{self.name}"
        lock = f"{pypi}/{self.name}.txt"
        # Write the pinned lock into place first (a quoted heredoc keeps the contents
        # literal), so the install needs no file to pre-exist in the container.
        write_lock = (
            f'mkdir -p "{pypi}" && cat > "{lock}" <<\'REPOSCAN_LOCK\'\n'
            f"{self.requirements}\n"
            f"REPOSCAN_LOCK"
        )
        lines = [
            write_lock,
            f'"{uv}" venv "{venv}"',
            f'"{uv}" pip install --python "{venv}" --require-hashes -r "{lock}"',
        ]
        lines += [
            f'ln -sf "{venv}/bin/{entrypoint}" "{install_root}/bin/{entrypoint}"'
            for entrypoint in self.entrypoints
        ]
        return lines


@dataclass(frozen=True)
class GoTool:
    """A tool built with `go install`, using the Go toolchain it names in `requires`.

    Pinned by its go.sum h1 hashes (`module_sum`, the module zip; `gomod_sum`, its
    go.mod), verified at build against a written go.sum with the public checksum DB
    off. `package` is the go install target (defaults to `module` when it is the
    module root); `module` is the module path the go.sum entries are keyed on.
    """

    name: str
    version: str
    module: str
    module_sum: str
    gomod_sum: str
    package: str = ""
    requires: tuple[Tool, ...] = ()
    kind: ClassVar[ToolKind] = ToolKind.GO

    def installed_path(self, install_root: str) -> str:
        return f"{install_root}/bin/{self.name}"

    def install_commands(self, platform: Platform, install_root: str) -> list[str]:
        # Build with the Go toolchain this tool depends on: its sole requirement is
        # the Go SDK, whose installed_path is the `go` binary.
        go = self.requires[0].installed_path(install_root)
        work = f"{install_root}/cache/go-build/{self.name}"
        package = self.package or self.module
        write_go_sum = (
            f"printf '%s v%s %s\\n%s v%s/go.mod %s\\n' "
            f'"{self.module}" "{self.version}" "{self.module_sum}" '
            f'"{self.module}" "{self.version}" "{self.gomod_sum}" > go.sum'
        )
        # One compound command (shared cwd): pin the module via a throwaway module's
        # go.sum and disable the public checksum DB, so the download is verified
        # against our stored hashes rather than sum.golang.org, then build from the
        # verified module cache.
        steps = [
            f'mkdir -p "{work}"',
            f'cd "{work}"',
            f'"{go}" mod init reposcan-build >/dev/null 2>&1 || true',
            f'"{go}" mod edit -require="{self.module}@v{self.version}"',
            write_go_sum,
            f'GOSUMDB=off GOFLAGS=-mod=mod "{go}" mod download "{self.module}"',
            f'GOBIN="{install_root}/bin" GOSUMDB=off GOFLAGS=-mod=mod '
            f'"{go}" install "{package}@v{self.version}"',
        ]
        return [" && ".join(steps)]

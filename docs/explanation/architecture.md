# Architecture

reposcan is a scan orchestrator, not a scanner. It drives a fixed set of pinned,
third-party tools, runs them in an isolated environment against a repository,
and merges their output into one report. This document describes the pieces and
why they are shaped the way they are.

## Threat model

The repository under scan is untrusted: it may contain hostile code, and merely
scanning it must not let that code run with any privilege it should not have.
Two design rules follow from this and recur below. The repository is mounted
read-only, and the tools run as an unprivileged user. The tools parse what is
committed rather than building or installing the repository, so scanning a
repository does not execute it.

## Execution contexts and backends

An execution context is a place reposcan can run commands, exposing a small
lifecycle: start, run, stop. There are three: a local context on the host,
Docker, and LXD. A backend decides whether its context is available and
constructs it; backend selection prefers Docker, then LXD, then local (see
[choose a backend](../how-to/choose-a-backend.md)).

The container backends bind-mount the target repository read-only at
`/scan/<name>`, keeping the repository's own directory name so tool output reads
naturally, and run each tool as an unprivileged user (UID 10000) via `setpriv`.
The local backend runs the tools as the invoking user with no isolation, which
is why it is discouraged for untrusted repositories.

## The tool image

Every pinned tool is installed into one image, so a container scan starts from a
single, reproducible environment. The image is content-addressed: its identity
is a hash of the build script, which embeds every tool's version, download URL,
and checksum. By default, a container backend pulls a published, digest-pinned
image from GHCR and reuses it. With `--image build`, it builds the image on
demand instead. It reuses the locally built image for future scans. A change to
any tool version or hash, or to the base image, yields a new hash and triggers a
rebuild.

## Tools

Each tool is defined once in a registry with its supply-chain pins inline:
native binaries by per-platform download URL and sha256, Go tools by their
checksum-database hashes, and PyPI tools by a hash-locked requirements file. The
tools are installed the same way whether baked into the image or installed onto
the host by `bootstrap`.

## The scan model

A scan is a set of tool invocations over a target plus a rule for consolidating
their outputs. The relationship between scans and tools is many-to-many: a scan
may drive several tools (the SBOM runs three), and a tool may be used by several
scans (trivy is used by SBOM and `sca`). A scan translates reposcan's parameters
into each tool's native flags, and its consolidation step merges the tools'
outputs into one artifact.

Security scans produce SARIF; the SBOM produces a CycloneDX inventory. The
security scans are exposed through the `scan` command and the SBOM through the
`sbom` command, though both use the same internal scan model. When several tools
contribute to one scan, their outputs are merged and de-duplicated.
De-duplication is performed by rule and location for SARIF and by package URL
for CycloneDX. Each entry is annotated with the tools that reported it. Because
the tools disagree on exit conventions, the commands present uniform exit codes
rather than passing a tool's code through.

The driver also handles two cross-cutting concerns for every scan so the scan
modules stay simple: it excludes git-ignored paths from filesystem-walking tools
(see [path exclusion](path-exclusion.md)), and it records each executed command
as provenance in the report.

## Dependency resolution

The SBOM and the `sca` scan see a full transitive dependency tree only from a
committed lockfile. When the scan has network access, a resolution pre-step runs
each ecosystem's package manager in resolve-only mode to generate the missing
lockfiles before the tools run. It runs no untrusted code by default and copies
the repository to a writable location first, since the mount is read-only. This
is the one place scanning may execute repository code, and only when explicitly
enabled with `--allow-code-execution`. The mechanism and its rationale are in
[SBOM generation](sbom-generation.md).

## Output

reposcan's default output is a concise table on stdout, `--format json` gives
the native SARIF or CycloneDX instead. Files written with `-o` are always
formatted as SARIF or CycloneDX JSON. The `render` command prints a saved report
as a table without re-running the scan.

Recording is separate from emitting. `--db FILE` appends the analysis to a
database, which is an accumulating history of a repository rather than a report:
it tracks the issues and components a scan reported, which analysis first and
last saw each of them, and every version a dependency has been pinned at.

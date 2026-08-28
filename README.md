# reposcan

`reposcan` is a tool for running security scans against a locally-cloned
repository.

By default, it executes all scans in ephemeral containers. It defaults to Docker
and falls back to LXD based on availability. It supports running scans directly
on the local host, though this is discouraged.

## Get started

- [Run your first scan](docs/tutorials/first-scan.md).
- [Scan with GitHub Actions](docs/how-to/scan-with-github-actions.md).
- [Scan with Launchpad CI](docs/how-to/scan-with-launchpad-ci.md).

The rest of the documentation is in [`docs/`](docs/index.md).

## Scans

`reposcan scan <type>` runs one of six scan types against a repository:

- `secrets`: leaked credentials in the git history or working tree.
- `sast`: static analysis of source code for security bugs.
- `iac`: misconfigurations in infrastructure-as-code.
- `workflow`: risks in CI/CD workflow definitions.
- `sca`: known vulnerabilities in dependencies.

Separately, `reposcan sbom` generates a software bill of materials for a
repository.

See the [scans reference](docs/reference/scans.md) for each scan's options and
output.

## Features

- **One interface over many tools**: reposcan aggregates many scanners behind a
  unified interface. Scanners are run in an ephemeral container to keep the host
  system clean.
- **Dependencies are resolved before they are inventoried:** SBOM tools are
  generally ineffective without a lockfile, so reposcan generates a lockfile if
  one does not already exist. (That means sbom results are somewhat speculative;
  running it on the same repo at two different points in time may resolve
  un-locked deps differently.)
- **Results normalization:** Findings from every tool are merged and
  deduplicated into a single SARIF/CycloneDX document, with a consistent format
  and metadata.
- **Findings tracked over time and across repositories:** `--db` records each
  analysis in a database that follows issues across point-in-time scans.
- **False positives suppressed in one place:** The reposcan-ignore file unifies
  false positive suppression across all tools drive by reposcan.

## Roadmap

Our planned work includes:

- **Automatic findings management:** Detect when an issue is fixed based on scan
  results. Support recording triage status and justification.
- **Commands for reading and writing the database:** To read the database, you
  must currently use a `sqlite` client; reposcan will add its own user-friendly
  commands.
- **Distribution methods:** A snap, and a plugin for `lpci`.
- **Wider coverage:** More SAST scanners behind the same interface.
- **Service mode:** Discover and scan the repositories of a GitHub organization
  on a schedule + a charmed distribution.

## Bundled tools and their licenses

`reposcan` drives a fixed set of third-party tools, each pinned by hash in
`src/reposcan/tools/registry.py`. Every tool remains under its own upstream
license, linked below:

| Tool                                                        | Purpose                                  | License                                                                       |
| ----------------------------------------------------------- | ---------------------------------------- | ----------------------------------------------------------------------------- |
| [semgrep](https://github.com/semgrep/semgrep)               | SAST                                     | [LGPL-2.1](https://github.com/semgrep/semgrep/blob/develop/LICENSE)           |
| [checkov](https://github.com/bridgecrewio/checkov)          | Infrastructure-as-code scanning          | [Apache-2.0](https://github.com/bridgecrewio/checkov/blob/main/LICENSE)       |
| [zizmor](https://github.com/zizmorcore/zizmor)              | GitHub Actions auditing                  | [MIT](https://github.com/zizmorcore/zizmor/blob/main/LICENSE)                 |
| [poutine](https://github.com/boostsecurityio/poutine)       | CI/CD pipeline auditing                  | [Apache-2.0](https://github.com/boostsecurityio/poutine/blob/main/LICENSE)    |
| [trufflehog](https://github.com/trufflesecurity/trufflehog) | Secret scanning                          | [AGPL-3.0](https://github.com/trufflesecurity/trufflehog/blob/main/LICENSE)   |
| [syft](https://github.com/anchore/syft)                     | SBOM generation                          | [Apache-2.0](https://github.com/anchore/syft/blob/main/LICENSE)               |
| [grype](https://github.com/anchore/grype)                   | Vulnerability scanning (SCA)             | [Apache-2.0](https://github.com/anchore/grype/blob/main/LICENSE)              |
| [trivy](https://github.com/aquasecurity/trivy)              | SBOM and vulnerability scanning          | [Apache-2.0](https://github.com/aquasecurity/trivy/blob/main/LICENSE)         |
| [cdxgen](https://github.com/CycloneDX/cdxgen)               | SBOM generation                          | [Apache-2.0](https://github.com/CycloneDX/cdxgen/blob/master/LICENSE)         |
| [govulncheck](https://github.com/golang/vuln)               | Go vulnerability scanning                | [BSD-3-Clause](https://github.com/golang/vuln/blob/master/LICENSE)            |
| [uv](https://github.com/astral-sh/uv)                       | Python installer (build prerequisite)    | [Apache-2.0 or MIT](https://github.com/astral-sh/uv/blob/main/LICENSE-APACHE) |
| [Go toolchain](https://go.dev)                              | Builds the Go tools (build prerequisite) | [BSD-3-Clause](https://go.dev/LICENSE)                                        |

### License compliance

`reposcan` uses each tool unmodified, as a separate executable across a process
boundary, which is mere aggregation rather than a derivative work, so no tool's
license reaches into its own source. See
[license compliance](docs/explanation/licensing.md) for the full explanation,
including the copyleft (AGPL-3.0, LGPL-2.1) cases and the redistribution
obligations for published images.

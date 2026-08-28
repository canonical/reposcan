# reposcan

`reposcan` is a tool for running security scans against a locally-cloned
repository.

By default, it executes all scans in ephemeral containers. It defaults to Docker
and falls back to LXD based on availability. It supports running scans
directly on the local host, though this is discouraged.

## Scans

`reposcan scan <type>` runs one of six scan types against a repository:

- `secrets`: leaked credentials in the git history or working tree.
- `sast`: static analysis of source code for security bugs.
- `iac`: misconfigurations in infrastructure-as-code.
- `workflow`: risks in CI/CD workflow definitions.
- `sca`: known vulnerabilities in dependencies.
- `sbom`: a CycloneDX software bill of materials.

See the [scans reference](docs/reference/scans.md) for each scan's options and
output.

## Documentation

Full documentation lives in [`docs/`](docs/index.md): tutorials, how-to guides,
a command and configuration reference, and design explanation. Start with
[your first scan](docs/tutorials/first-scan.md) or the
[architecture](docs/explanation/architecture.md).

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

# Scans

Each scan runs one or more tools against a repository and consolidates their
output into a single SARIF report. Where several tools contribute, their
findings are merged and de-duplicated, and each finding is annotated with the
tools that reported it.

Scans run via `reposcan scan` and exit `0` (nothing at or above `--fail-on`),
`3` (a finding at or above `--fail-on`), `1` (internal error), or `2` (usage
error). All accept the shared output options (`-o`, `--db`, `-f/--format`,
`-n/--limit`, `--wrap`); see [commands](commands.md).

## secrets

Leaked credentials, via trufflehog. Emits SARIF. Options:

- `--mode <history|filesystem>`: scan the git history or only the working-tree
  files. When unset, it uses history for a git repository and the filesystem
  otherwise (so a non-git directory is scanned rather than failing).
- `--depth <N>`: in history mode, scan only the most recent N commits (default:
  all).

## sast

Static analysis of source code, via semgrep. Emits SARIF.

## iac

Infrastructure-as-code checks, via checkov. Emits SARIF.

## workflow

CI/CD workflow auditing, via zizmor and poutine. Emits SARIF.

## sca

Dependency vulnerabilities, via trivy, grype, and govulncheck. Emits SARIF.
govulncheck applies only to Go modules and is skipped on other repositories.
This scan resolves dependencies first and accepts `--allow-code-execution` and
`--include-dev-dependencies`.

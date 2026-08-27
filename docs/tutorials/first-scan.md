# Your first scan

This tutorial installs reposcan and runs a scan against a repository you have
cloned locally. By the end you will have produced a report and know how to
change its format.

## Prerequisites

reposcan runs each scan in an ephemeral container, so you need one container
backend available: Docker (preferred) or LXD. It can also run directly on the
host, but that is discouraged and not used here. Installing the CLI needs Python
3.10 or newer.

## Install the CLI

Install `reposcan` directly from the repository with pipx or uv. It has no
runtime Python dependencies.

    pipx install git+https://github.com/canonical/repo-scanner
    # or: uv tool install git+https://github.com/canonical/repo-scanner

Confirm it is on your path:

    reposcan --help

## Run a scan

Point a scan at a repository directory. The first container scan pulls the
published tool image (a few seconds), or builds it locally with `--image build`;
later scans reuse it.

    reposcan scan secrets ./path/to/repo

The `secrets` scan searches the repository's git history for leaked credentials
with trufflehog. reposcan prints a table of findings and exits 3 when it finds
any, or 0 when it finds none.

## Read the report

By default reposcan prints a concise table to stdout. To keep the full,
machine-readable report, choose a format and write it to a file:

    reposcan scan secrets ./path/to/repo -o findings.sarif

Security scans emit SARIF. The `render` command prints a saved report as a
table without re-running the scan:

    reposcan render findings.sarif

## Next steps

- Run the other scan types: see [run a scan](../how-to/run-a-scan.md).
- Understand what happens behind a scan: see the
  [architecture](../explanation/architecture.md).

# reposcan documentation

reposcan runs a fixed set of security scanners against a locally-cloned
repository, each in an ephemeral, unprivileged container, and merges their
output into one report. It drives pinned, third-party tools across five scan
types (secrets, static analysis, infrastructure-as-code, CI/CD workflows, and
dependency vulnerabilities), and generates a software bill of materials.

This documentation follows the four [Diataxis](https://diataxis.fr/) categories.

## Tutorials

Learning-oriented lessons that walk through a task end to end.

- [Your first scan](tutorials/first-scan.md): install reposcan and produce a
  report.

## How-to guides

Task-oriented recipes for a specific goal.

- [Run a scan](how-to/run-a-scan.md)
- [Generate an SBOM](how-to/generate-an-sbom.md)
- [Select a backend](how-to/select-a-backend.md)
- [Use a published image](how-to/use-a-published-image.md)
- [Scan with GitHub Actions](how-to/scan-with-github-actions.md)
- [Scan with Launchpad CI](how-to/scan-with-launchpad-ci.md)
- [Ignore false positives](how-to/ignore-findings.md)

## Reference

Precise descriptions of the CLI and configuration options.

- [Commands](reference/commands.md)
- [Scans](reference/scans.md)
- [Configuration](reference/configuration.md)

## Explanation

The design and the reasoning behind it.

- [Architecture](explanation/architecture.md)
- [SBOM generation](explanation/sbom-generation.md)
- [Path exclusion](explanation/path-exclusion.md)
- [License compliance](explanation/licensing.md)

The project overview and the bundled tools with their licenses are in the
repository [README](../README.md).

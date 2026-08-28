# Scan with GitHub Actions

The repository ships a composite Action to run reposcan against a checked-out
repository. It runs most scans by default (secrets, sast, iac, workflow, and
sca), and uploads the scanning results. If the workflow is configured to do so
-- and given a token with the necessary privileges -- it will also write results
to the code-scanning pane and/or to a pull-request comment. (The code-scanning
pane results are enabled by default, while the pull-request comment is disabled
by default.)

## Basic usage

You can create your own workflow, or copy the one in this repository
(`.github/workflows/reposcan.yml`).

Example workflow:

```yaml
name: security-scan
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # upload SARIF to the code-scanning pane
  pull-requests: write     # comment on the PR when the upload is unavailable

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: canonical/reposcan@v1
```

The runner needs Docker (included in the `ubuntu-latest` image); reposcan runs
pinned tools inside a container image.

## Choosing scans

Every scan is a boolean input. All scans are on by default, with the exception
of `sbom`, which produces a dependency inventory, not security findings.

```yaml
      - uses: canonical/reposcan@v1
        with:
          secrets: true
          sast: true
          iac: false
          workflow: false
          sca: true
          sbom: true
```

## Findings threshold

By default, the job fails when a finding at or above SARIF level `error` is
reported. Set `fail-on` to `warning`, `note`, or `none` (report but never fail)
to change the threshold. A tool or setup error always fails the job.

```yaml
      - uses: canonical/reposcan@v1
        with:
          fail-on: none   # report-only: never fail on findings
```

## Results

The action's results are always uploaded as a job artifact and printed in the
job log. Depending on your configuration and the token provided, they may also
be written to:

1. GitHub's code-scanning pane (needs the `security-events: write` permission
   and code scanning enabled).
1. A pull-request comment (needs `pull-requests: write`).

On a pull request from a fork, the `GITHUB_TOKEN` is always read-only,
regardless of the `permissions` block. Neither the code-scanning upload nor the
pull-request comment will work in this case.

## Inputs

| Input           | Default        | Meaning                                                       |
| --------------- | -------------- | ------------------------------------------------------------- |
| `secrets`       | `true`         | Run the `secrets` scan.                                       |
| `sast`          | `true`         | Run the `sast` scan.                                          |
| `iac`           | `true`         | Run the `iac` scan.                                           |
| `workflow`      | `true`         | Run the `workflow` scan.                                      |
| `sca`           | `true`         | Run the `sca` scan.                                           |
| `sbom`          | `false`        | Generate a CycloneDX SBOM (artifact only).                    |
| `code-scanning` | `true`         | Upload findings SARIF to the code-scanning pane.              |
| `pr-comment`    | `false`        | Post the results summary as a pull-request comment.           |
| `path`          | `.`            | Directory to scan (the checked-out repository).               |
| `image`         | `canonical`    | Tool image: an OCI reference, `canonical`, or `build`.        |
| `backend`       | `docker`       | Execution backend tools run in.                               |
| `fail-on`       | `error`        | Fail at/above this level: `error`, `warning`, `note`, `none`. |
| `token`         | `github.token` | Token for the SARIF upload and PR comment.                    |

# Commands

The CLI is `reposcan`, invoked as:

```
reposcan <command> [options]
```

A command's parameters should follow the command. Global options may appear
anywhere on the command line.

## Global options

Global options resolve from the command line, then environment variables, then
saved config, then the built-in default (see [configuration](configuration.md)).

### `-v`, `--verbosity <level>`

The lowest log level written to stderr.

| Property       | Description                                             |
| -------------- | ------------------------------------------------------- |
| Allowed values | one of `debug`, `info`, `warning`, `error`, `critical`. |
| Env var to set | `REPOSCAN_VERBOSITY`.                                   |
| Config key     | `verbosity`                                             |
| Default value  | `info`.                                                 |

### `--backend <name>`

Which backend to use. Containers run each scan in an ephemeral image; `local`
runs them on the host.

| Property       | Description                                              |
| -------------- | -------------------------------------------------------- |
| Allowed values | one of `auto`, `docker`, `lxd`, `local`.                 |
| Env var to set | `REPOSCAN_BACKEND`.                                      |
| Config key     | `backend`                                                |
| Default value  | `auto` -- Docker, then LXD, then local, by availability. |

### `--uid <UID>`

The identity in-container processes run as. By default, reposcan runs as the
invoking host user (with its groups). The local backend ignores this setting and
always runs as the invoking user.

| Property       | Description             |
| -------------- | ----------------------- |
| Allowed values | a non-negative integer. |
| Env var to set | `REPOSCAN_UID`.         |
| Config key     | `uid`                   |
| Default value  | the invoking host user. |

### `--image <ref>`

The image to run scans in. Not supported for backend=local. See
[use a published image](../how-to/use-a-published-image.md).

| Property       | Description                                                                    |
| -------------- | ------------------------------------------------------------------------------ |
| Allowed values | an OCI reference, `canonical` (the official image), or `build` (build locally) |
| Env var to set | `REPOSCAN_IMAGE`.                                                              |
| Config key     | `image`                                                                        |
| Default value  | `canonical` -- pull the digest-pinned published image from GHCR.               |

## scan

`reposcan scan <types> <path>` runs one or more scans against a repository
directory and maps the outcome to an exit code. `<types>` is a scan type or
several comma-separated (`reposcan scan sast,secrets ./repo`); they run in one
backend session and their findings are consolidated into a single SARIF report.
Types are `secrets`, `sast`, `iac`, `workflow`, and `sca`, or `all` to run every
type; see the [scans reference](scans.md) for each scan's tools and options.
Common options:

- `-o, --output <FILE>`: write the report to a file instead of stdout.
- `-f, --format <fmt>`: `table` (default, stdout), `json`, or `sqlite`. When
  writing to a file with no `--format`, the format is inferred from the file's
  suffix (`.json`/`.sarif`, `.sqlite`/`.sqlite3`/`.db`, `.txt`); an unrecognized
  suffix is rejected before the scan runs.
- `-n, --limit <N>`: maximum table rows shown (default 20).
- `--wrap <N>`: maximum lines a long table cell may wrap across (default 4; `1`
  keeps each cell to a single clipped line).
- `--ignore-file <FILE>`: reposcan ignorefile for false positives (default
  `.reposcan-ignore`). See
  [ignore false positives](../how-to/ignore-findings.md).
- `--no-ignore-file`: do not read any reposcan ignorefile.
- `--include-dev-dependencies`: for `sca` only, resolve development
  dependencies.
- `--allow-code-execution`: for `sca` only, let dependency resolution build
  source packages, which may run untrusted code (off by default).
- `--mode <history|filesystem>`, `--depth <N>`: for `secrets` only; see the
  [scans reference](scans.md).

A scan-specific option applies only when its scan is among the requested types;
passing one otherwise (for example `--depth` without `secrets`) is a usage
error.

Exit codes: `0` ran with no findings, `3` findings, `1` scan or tool error, `2`
usage error.

## sbom

`reposcan sbom <path>` builds a CycloneDX software bill of materials for a
repository. An SBOM is an inventory rather than a pass/fail check, so it always
exits `0` when it runs. It shares the `-o/--output`, `-f/--format`,
`-n/--limit`, and `--wrap` options with `scan`, and takes
`--include-dev-dependencies` and `--allow-code-execution`. See the
[Generate an SBOM](../how-to/generate-an-sbom.md) guide and
[SBOM generation](../explanation/sbom-generation.md).

Exit codes: `0` on success, `1` on a tool or write error, `2` usage error.

## render

`reposcan render <path>` converts a saved report between formats without
re-running a scan. The input is a SARIF or CycloneDX JSON file, or a reposcan
sqlite database (detected by content). Options: `-o/--output`, `-f/--format`,
`-n/--limit`, and `--wrap`, as for `scan`. Runs locally with no backend.

## exec

`reposcan exec -- <command>` runs an arbitrary command in the selected execution
context. Separate the command from reposcan's own options with `--`. Option:
`--timeout <SECONDS>` kills the command after that long.

```
reposcan exec -- trivy --version
reposcan exec -- semgrep -h
```

The scanning tools are symlinked onto `/usr/local/bin` in the tool image, so
they are on `PATH` and can be run by name. Use `reposcan tools` to list them.

## tools

`reposcan tools` lists the scanning tools and whether each is installed in the
selected backend.

## bootstrap

`reposcan bootstrap [tools...]` installs tools onto the host (or into the
backend when `--backend` is given). With no tool names, it installs all of them.
A host install is confirmed interactively unless `--confirm` is passed. The
container backends do not need this; they build or pull the tool image.

## image

- `reposcan image build [--backend <name>]`: build (or rebuild) the tool image
  and print its reference. Reuses an existing image when nothing changed.
- `reposcan image cache list`: list the recorded built and pulled images.
- `reposcan image cache remove <reference>`: remove one record.
- `reposcan image cache clear`: remove all records.

See [use a published image](../how-to/use-a-published-image.md).

## config

Persist and inspect settings (see [configuration](configuration.md)).

- `reposcan config set <key> <value>`
- `reposcan config get [key]`: one value, or all when no key is given.
- `reposcan config unset <key>`
- `reposcan config keys`: list the supported keys.
- `reposcan config options <key>`: list a key's allowed values.

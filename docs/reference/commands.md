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

### `--env <NAME[=VALUE]>`

Pass an environment variable to all subprocess commands. `NAME` forwards the
host environment's value if set; `NAME=VALUE` sets it to `VALUE`. Repeat the
option for several variables.

| Property       | Description                                                    |
| -------------- | -------------------------------------------------------------- |
| Allowed values | `NAME`, or `NAME=VALUE`.                                       |
| Env var to set | `REPOSCAN_ENV` (one variable).                                 |
| Config key     | `env` (one variable via `config set`)                          |
| Default value  | none -- see [select a backend](../how-to/select-a-backend.md). |

## scan

`reposcan scan <types> <path>` runs one or more scans against a repository
directory and maps the outcome to an exit code. `<types>` is a scan type or
several comma-separated (`reposcan scan sast,secrets ./repo`); they run in one
backend session and their findings are consolidated into a single SARIF report.
Types are `secrets`, `sast`, `iac`, `workflow`, and `sca`, or `all` to run every
type; see the [scans reference](scans.md) for each scan's tools and options.
Common options:

- `-o, --output <FILE>`: write the report to a file instead of stdout. Files are
  always formatted as JSON (SARIF for scans, CycloneDX for `sbom`).
- `--db <FILE>`: record the analysis in the database at `FILE`, creating it if
  absent. Independent of `-o`. See [the database](#the-database).
- `-f, --format <fmt>`: `table` (the default) or `json`, for stdout only. To put
  a table in a file, redirect: `reposcan scan sast ./repo > report.txt`.
- `-n, --limit <N>`: maximum table rows shown (default 20).
- `--wrap <N>`: maximum lines a long table cell may wrap across (default 4; `1`
  keeps each cell to a single clipped line).
- `--ignore-file <FILE>`: reposcan ignorefile for false positives (default
  `.reposcan-ignore`). See
  [ignore false positives](../how-to/ignore-findings.md).
- `--no-ignore-file`: do not read any reposcan ignorefile.
- `--fail-on <error|warning|note|none>`: exit non-zero only for a finding at or
  above this level (default `note`, so any finding fails); `none` never fails.
- `--include-dev-dependencies`: for `sca` only, resolve development
  dependencies.
- `--allow-code-execution`: for `sca` only, let dependency resolution build
  source packages, which may run untrusted code (off by default).
- `--mode <history|filesystem>`, `--depth <N>`: for `secrets` only; see the
  [scans reference](scans.md).

A scan-specific option applies only when its scan is among the requested types;
passing one otherwise (for example `--depth` without `secrets`) is a usage
error.

Exit codes: `0` nothing at or above `--fail-on`, `3` a finding at or above
`--fail-on`, `1` scan or tool error, `2` usage error.

## sbom

`reposcan sbom <path>` builds a CycloneDX software bill of materials for a
repository. An SBOM is an inventory rather than a pass/fail check, so it always
exits `0` when it runs. It shares the `-o/--output`, `--db`, `-f/--format`,
`-n/--limit`, and `--wrap` options with `scan`, and takes
`--include-dev-dependencies` and `--allow-code-execution`. See the
[Generate an SBOM](../how-to/generate-an-sbom.md) guide and
[SBOM generation](../explanation/sbom-generation.md).

Exit codes: `0` on success, `1` on a tool or write error, `2` usage error.

## render

`reposcan render <path>` prints a saved SARIF or CycloneDX JSON report as a
table, without re-running the scan. Options: `-n/--limit` and `--wrap`, as for
`scan`. Runs locally with no backend.

## the database

`--db FILE` records an analysis in a SQLite database: one pass of reposcan over
a repository, holding one scan per scan type. Re-running against the same file
appends a second analysis without overwriting.

## exec

`reposcan exec -- <command>` runs an arbitrary command in the selected execution
context. Separate the command from reposcan's own options with `--`. Option:
`--timeout <SECONDS>` kills the command after that long.

```
reposcan exec -- trivy --version
reposcan exec -- semgrep -h
```

The scanning tools are symlinked onto `/usr/local/bin` in the tool image, so
they are on `PATH` and can be run by name. Use `reposcan list-tools` to list
them.

By default, most host system environment variables are _not_ passed through. See
`--env`.

## list-tools

`reposcan list-tools` lists the scanning tools and whether each is installed in
the selected backend.

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

## gh

A command group for interacting with GitHub repositories. Needs the `service`
extra: `pipx install "reposcan[service]"`.

Every `gh` command supports (and requires) `--org`, `--enterprise`, or both;
giving neither is a usage error.

- `--org <NAME>`: an organization to read. Env var: `REPOSCAN_GH_ORG`.
- `--enterprise <SLUG>`: an enterprise whose organizations to read. Env var:
  `REPOSCAN_GH_ENTERPRISE`.
- `REPOSCAN_GH_TOKEN`: the actual token. Preferred, and used whenever it is set.
- `--token-file <FILE>`: read a GitHub token from `FILE`, used only when
  `REPOSCAN_GH_TOKEN` is unset. Env var: `REPOSCAN_GH_TOKEN_FILE`.

Without a token, API requests are anonymous, so they find only public
repositories and have a much smaller rate limit.

`reposcan gh list-repos` lists repositories, one per line with its default
branch and clone URL. Additional options:

- `--include-archived`: also list archived repositories, skipped by default.
- `--exclude-forks`: skip forks, which are listed by default.
- `--exclude <GLOB,GLOB>`: skip repositories whose `owner/name` matches a glob.
- `-o, --output <FILE>`: write selected repositories to `FILE` as JSON.
- `-f, --format <fmt>`: `table` (the default) or `json`, for stdout only.
- `-n, --limit <N>`: maximum table rows shown (default 20).
- `--wrap <N>`: maximum lines a long table cell may wrap across (default 4).

Disabled repositories are never listed; they cannot be cloned.

Exit codes: `0` on success, `1` when GitHub could not be read or the extra is
not installed, `2` for a usage error.

## config

Persist and inspect settings (see [configuration](configuration.md)).

- `reposcan config set <key> <value>`
- `reposcan config get [key]`: one value, or all when no key is given.
- `reposcan config unset <key>`
- `reposcan config list-keys`: list the supported keys.
- `reposcan config list-options <key>`: list a key's allowed values.

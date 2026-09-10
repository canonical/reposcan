# Configuration

reposcan reads a small set of settings, each resolvable from four sources.
Persisted settings live in a JSON object at
`$XDG_CONFIG_HOME/reposcan/config.json` (default
`~/.config/reposcan/config.json`) and are managed with the
[`config`](commands.md#config) commands.

## Resolution order

Each setting resolves from, in order of precedence:

1. command-line options
1. `REPOSCAN_*` environment variables
1. saved config values
1. built-in defaults

## Environment variables

Most options can be set with `REPOSCAN_<name>`, where `<name>` is the
uppercased option name with hyphens replaced by underscores. For example,
`--backend` can be set with `REPOSCAN_BACKEND`. Positional arguments,
remainders, and `--env` are never read from the environment.

Some command options use a different format:

- `gh` commands support `REPOSCAN_GH_TOKEN` (not configurable as a parameter),
  `REPOSCAN_GH_TOKEN_FILE`, `REPOSCAN_GH_ORG`, `REPOSCAN_GH_ENTERPRISE`,
  and `REPOSCAN_GH_REPO`.

## Config options

The list of options that can be set in persistent configuration is exactly the
list of global options in [commands](./commands.md)

## Storage locations

reposcan follows the XDG base directory convention:

- Config: `$XDG_CONFIG_HOME/reposcan/` (default `~/.config/reposcan/`).
- Host-installed tools (from `bootstrap`): `$XDG_DATA_HOME/reposcan/` (default
  `~/.local/share/reposcan/`).
- Dependency-resolution scratch copies (local backend-only):
  `$XDG_CACHE_HOME/reposcan/` (default `~/.cache/reposcan/`).

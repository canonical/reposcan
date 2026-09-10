# Select a backend

A backend is where the tools run. reposcan supports three: `docker` and `lxd`
run each scan in an ephemeral container. `local` runs the tools directly on the
host.

## Let reposcan choose

With no backend set, reposcan selects one automatically by availability, in the
order Docker, then LXD, then local.

## Set the backend explicitly

The backend resolves from, in order of precedence: the `--backend` option, the
`REPOSCAN_BACKEND` environment variable, the saved config, and finally `auto`.

```
reposcan --backend docker scan sast ./repo     # one run
export REPOSCAN_BACKEND=docker                 # this shell
reposcan config set backend docker             # persisted
```

`--backend` accepts `auto`, `docker`, `lxd`, or `local`. When two sources
disagree, reposcan logs which one won.

## Use the local backend

The local backend runs tools on the host with no container isolation, which
means all tools must be installed locally. This can be achieved with
[`bootstrap`](../reference/commands.md#bootstrap):

```
reposcan bootstrap
reposcan --backend local scan sast ./repo
```

Note: environment variables are stripped for processes executed via the local
backend: only `HOME`, `PATH`, the locale, the temp directory, the XDG base
directories, and the proxy and CA settings are passed through. Anything else in
the environment is dropped. This also applies to
[`exec`](../reference/commands.md#exec). Additional environment variables can be
explicitly passed through with `--env`.

## Set the in-container user

Container scans run as the invoking host user by default, with that user's
groups, so a repository stays as readable inside the container as it is on the
host. Override the UID to run in-container processes as a different user. The
local backend ignores the UID parameter and runs with your UID.

```
reposcan --uid 1000 sbom ./repo
```

Like the backend, the UID resolves from `--uid`, then `REPOSCAN_UID`, then the
saved `uid` config, then the default. See
[configuration](../reference/configuration.md) for all of the resolved settings.

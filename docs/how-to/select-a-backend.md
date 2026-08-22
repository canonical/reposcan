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

The local backend runs the tools on the host with no container isolation, so it
requires the tools to be installed there first and it is discouraged for
untrusted repositories. Install the tools onto the host with
[`bootstrap`](../reference/commands.md#bootstrap):

```
reposcan bootstrap
reposcan --backend local scan sast ./repo
```

The container backends need no bootstrap: they build or pull the tool image on
demand (see [use a published image](use-a-published-image.md)).

## Set the in-container user

Container scans run as an unprivileged user (UID 10000) by default so that
untrusted repository code cannot run as root. Override the UID when a repository
has files that user cannot read; the local backend ignores it and runs as you.

```
reposcan --uid 1000 sbom ./repo
```

Like the backend, the UID resolves from `--uid`, then `REPOSCAN_UID`, then the
saved `uid` config, then the default. See
[configuration](../reference/configuration.md) for all of the resolved settings.

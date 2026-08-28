# SBOM generation

reposcan produces a CycloneDX software bill of materials by running three tools
-- syft 1.46.0, trivy 0.72.0, and cdxgen 12.7.0 -- over a source directory and
merging their output into a single inventory that is de-duplicated by package
URL and annotated with which tools reported each component. Those three tools
parse the manifests and lockfiles committed to the repository and do not build
or install it.

Because a bare manifest lists only direct dependencies, or none, a repository
without a lockfile would otherwise yield incomplete or no transitive coverage.
reposcan closes that gap with a dependency-resolution step that runs before the
tools (see "Dependency resolution"). When the scan has network access, it
invokes each ecosystem's own package manager to generate the missing lockfiles.
That step runs no untrusted code by default, resolving from registry metadata,
but the `--allow-code-execution` flag configurably lets it build source
packages, which does execute untrusted repository and dependency code.

## Context

None of the SBOM or SCA tools turns a bare manifest into a transitive graph;
each reads a committed lockfile or reports nothing. Producing a resolved graph
from a manifest is a package manager's job, for two reasons:

1. The transitive metadata is not in the repository. A manifest lists only its
   direct dependencies, and each of those dependencies declares its own
   requirements on the package registry (the PyPI JSON API, npm packuments), so
   resolving a manifest means querying that registry.
   ([PyPI API](https://docs.pypi.org/api/json/))

1. Resolution is also an NP-hard constraint problem (PubGrub and backtracking),
   so a tool that resolved manifests would be reimplementing a package manager's
   solver; the tools defer to the real resolver instead (
   [PubGrub](https://github.com/dart-lang/pub/blob/master/doc/solver.md)).

For Python, resolution is not even a pure read: resolving an sdist can execute
arbitrary build code (`setup.py` or a PEP 517 backend) unless the index serves
metadata under PEP 658 ([PEP 658](https://peps.python.org/pep-0658/),
[pip secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/)).

Lockfile-only parsers (syft, trivy) report a graph only from a committed
lockfile. Resolver-invoking tools produce a graph from a bare manifest by
running a package manager. Examples: ORT, Mend, and FOSSA dynamic strategies,
Black Duck CLI detectors, Microsoft component-detection's pip path
(`pip install --report`), and cdxgen with `--lifecycle build`.

Package-manager resolve-only commands such as `pip install --dry-run --report`,
`pip-compile`, `uv pip compile`, `npm install --package-lock-only`, and
`poetry lock` resolve without installing but still query the registry and may
build sdists.

Go is the exception: MVS is deterministic, so a committed `go.mod` already
encodes the resolved graph and no resolver is needed.

Maintainers intentionally decline to add manifest resolution to the SBOM tools.
trivy's maintainer wrote, "It would be a significant effort to mimic the
behavior of pip. We did it for maven, but it was really challenging."
([trivy#4727](https://github.com/aquasecurity/trivy/discussions/4727),
[syft#3010](https://github.com/anchore/syft/issues/3010),
[cdxgen#375](https://github.com/CycloneDX/cdxgen/issues/375))

## Tool invocation

reposcan runs all three tools with the target repository as the working
directory, as an unprivileged user, and with git-ignored directories excluded
(see `path-exclusion.md`). Each tool also takes dev-dependency flags that vary
with `--include-dev-dependencies` (see "Development dependencies").

- syft: `syft dir:<target> -o cyclonedx-json`, with env
  `SYFT_CHECK_FOR_APP_UPDATE=false`,
  `SYFT_PYTHON_GUESS_UNPINNED_REQUIREMENTS=true`, and
  `--override-default-catalogers all`.
- trivy: `trivy fs --format cyclonedx <target>`.
- cdxgen:
  `cdxgen --no-install-deps --lifecycle pre-build --no-banner -o <file> <target>`,
  with env `CDXGEN_SECURE_MODE=true`.

## Development dependencies

By default reposcan reports only production dependencies; the
`--include-dev-dependencies` flag (on the `sbom` and `sca` scans) also reports
development dependencies. The tools disagree on both their defaults and on how
the setting is exposed:

- trivy excludes dev dependencies by default and includes them with the
  `--include-dev-deps` CLI flag (npm, yarn, pnpm, bun, poetry, uv).
  ([coverage](https://trivy.dev/docs/latest/coverage/language/nodejs/))
- syft excludes JavaScript dev dependencies by default and includes them via the
  `SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true` environment variable. There is
  no CLI flag, and the setting is JavaScript-only.
  ([config](https://oss.anchore.com/docs/reference/syft/configuration/))
- cdxgen includes dev dependencies by default, so reposcan adds
  `--required-only` to keep production scope only, and drops it when dev
  dependencies are requested.
  ([ENV.md](https://github.com/CycloneDX/cdxgen/blob/v12.7.0/docs/ENV.md))

For the SCA scan (trivy, grype, govulncheck) only trivy is configurable: grype
has no dev/production filter
([grype#1643](https://github.com/anchore/grype/issues/1643)), and govulncheck
scans Go, which has no development/production split.

A dev dependency that only one tool reports still appears in the merged,
de-duplicated output, annotated with the tool that found it.

## Dependency resolution

When the scan environment has network access and the repository does not contain
a lockfile, reposcan generates one. It runs each ecosystem's package manager(s)
in resolve-only mode, using the per-ecosystem commands listed under "Resolvers"
below. This improves SBOM and SCA scans: an SBOM gains the transitive inventory,
and SCA (grype and trivy) matches vulnerabilities against all dependencies
rather than direct dependencies alone.

The pinned resolver tools are uv 0.11.26, poetry 2.4.1 (with
poetry-plugin-export 1.10.0), pipenv 2026.7.1, Node 24.19.0 (whose bundled npm
is used), and pnpm 11.21.0.

### Mechanism

Discovery uses one `git ls-files` on the target, which lists every tracked
manifest at any depth so that git-ignored build directories such as `.venv` and
`node_modules` are never mistaken for sources. Because the repository mount is
read-only, reposcan copies the repository to `/resolved-deps/<repo-name>`,
writes the generated lockfiles into that copy, and runs the scan against the
copy; the name is preserved so finding locations still read as `<repo>/...`. The
step is best-effort, so any failure -- no network, an unsatisfiable resolve, or
a manifest no package manager handles -- leaves that manifest unchanged and the
scan still runs, falling back to the lockfile-or-nothing behavior described
under "Limits and gaps". No untrusted code runs by default: uv resolves
wheel-only (`--only-binary :all:`, metadata only), npm and pnpm pass
`--ignore-scripts`, and poetry and pipenv resolve registry metadata. The
`--allow-code-execution` scan flag opts into building source packages -- uv
retries without `--only-binary` -- for the source-only packages that a
wheel-only resolve cannot satisfy.

### Resolvers

Python has three resolvers.

- uv resolves a PEP 621 `[project]` `pyproject.toml`, `requirements*.{txt,in}`,
  and a static `setup.cfg` with `uv pip compile <input> --only-binary :all:`,
  writing `reposcan-resolved.*.requirements.txt`. It is skipped when the
  directory already has `uv.lock`, `poetry.lock`, `pdm.lock`, `Pipfile.lock`,
  `pylock.toml`, or a fully-`==`-pinned `requirements.txt`.
  ([docs](https://docs.astral.sh/uv/pip/compile/))
- poetry resolves a legacy `[tool.poetry]` `pyproject.toml` (one with no
  `[project]`) with `poetry lock` and
  `poetry export -f requirements.txt --without-hashes`, writing
  `reposcan-resolved.poetry.requirements.txt`. It is skipped when a
  `poetry.lock` is present.
  ([plugin](https://github.com/python-poetry/poetry-plugin-export))
- pipenv resolves a `Pipfile` with `pipenv lock` and `pipenv requirements`,
  writing `reposcan-resolved.pipfile.requirements.txt`. It is skipped when a
  `Pipfile.lock` is present.
  ([docs](https://pipenv.pypa.io/en/latest/commands.html#requirements))

JavaScript and TypeScript have two.

- npm resolves a `package.json` -- npm, yarn, and bun all keep their
  dependencies there -- with `npm install --package-lock-only --ignore-scripts`,
  writing `package-lock.json`. It is skipped when the directory already has
  `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`,
  `bun.lockb`, `bun.lock`, or a `pnpm-workspace.yaml` (which is pnpm's job).
  ([docs](https://docs.npmjs.com/cli/v10/commands/npm-install))
- pnpm resolves a `pnpm-workspace.yaml`, whose catalogs npm cannot read, with
  `pnpm install --lockfile-only --ignore-scripts`, writing `pnpm-lock.yaml`. It
  is skipped when a `pnpm-lock.yaml` is present.
  ([docs](https://pnpm.io/cli/install))

Go has no resolver, for the reason below:

Go needs no pre-step. A committed `go.mod` (Go 1.17 or newer, tidied) already
lists the full transitive module set at their MVS-selected versions, with
indirect modules marked `// indirect`, which syft and trivy read directly (see
the Go coverage below). `go mod download` would only add licenses,
dependency-graph edges, and `h1:` digests.
([docs](https://go.dev/ref/mod#graph-pruning))

The generated files (`package-lock.json`, `pnpm-lock.yaml`, and
`*requirements*.txt`) are picked up by the SBOM/SCA tools, with one caveat:
trivy only picks up the exact name '`requirements.txt`' and misses the reposcan
lockfile. syft and cdxgen both find it.

### Design

Each ecosystem is a `Resolver` in `scans/resolve/`: a `Resolver` base class
coordinates the ecosystem and composes `PackageManager`s (the tools above), and
each package manager owns its `can_resolve` (which manifests it handles, minus
already-locked ones) and its `resolve` (the command). A directory is offered to
every package manager that claims it, so a directory holding both a
`requirements.txt` and a `Pipfile` is resolved by both. Workspace handling is
implicit: every unlocked `package.json` directory is resolved, and the SBOM
merge de-duplicates by package URL.

## Coverage by ecosystem

In the summaries below, "full graph" means transitive dependencies are captured,
"direct only" means only the manifest's own list, and "nothing" means no
dependency components are produced.

### Go

- Files read: syft reads `go.mod` (glob) and `go.sum` (a sibling, for hashes);
  trivy reads `go.mod` and `go.sum`; cdxgen reads `go.mod`, `go.sum`,
  `Gopkg.lock`, and `vendor/modules.txt`.
- From `go.mod` alone: syft gives the full graph (direct + `// indirect`); trivy
  is full on Go 1.17 or newer and direct-only below that; cdxgen is full but
  only by running `go list`/`go mod graph`.
- Transitive source: syft uses the `go.mod` require block, richer when
  `use-packages-lib` runs the go toolchain; trivy uses `go.mod` (1.17 or newer);
  cdxgen uses the toolchain, or the `go.mod` text as a fallback. cdxgen runs
  `go` even with `--no-install-deps`, and syft may also shell out to `go`.
- Sources: syft
  ([config](https://github.com/anchore/syft/blob/v1.46.0/syft/pkg/cataloger/golang/config.go#L52-L53)),
  trivy ([coverage](https://trivy.dev/docs/latest/coverage/language/golang/)),
  cdxgen
  ([src](https://github.com/CycloneDX/cdxgen/blob/v12.7.0/lib/cli/index.js#L5466-L5478)).

### Python

- Manifests: syft reads `**/*requirements*.txt` and `setup.py`; trivy reads
  `requirements.txt`; cdxgen reads `requirements.txt` and `setup.py` (regex
  fallback).
- Lockfiles: syft reads `poetry.lock`, `Pipfile.lock`, `uv.lock`, and
  `pdm.lock`; trivy reads `Pipfile.lock`, `poetry.lock`, and `uv.lock`; cdxgen
  reads `poetry.lock`, `pdm.lock`, `uv.lock`, `pylock.toml`, and `Pipfile.lock`.
- `pyproject.toml`: syft does not parse it at all; trivy treats it as a
  companion only, not a package source; cdxgen parses it but discards the
  dependencies unless installing.
- `requirements.txt`: syft gives direct dependencies (unpinned entries dropped
  unless guess-unpinned); trivy gives direct dependencies (`==` only unless
  `--detection-priority comprehensive`); cdxgen gives direct dependencies, per
  named package.
- Transitive dependencies come from lockfiles only, for all three tools.
- A bare `pyproject.toml` with no lockfile yields nothing from any tool (from
  cdxgen, parent metadata only).
- Sources: syft
  ([cataloger.go](https://github.com/anchore/syft/blob/v1.46.0/syft/pkg/cataloger/python/cataloger.go#L14-L44)),
  trivy ([coverage](https://trivy.dev/docs/latest/coverage/language/python/)),
  cdxgen
  ([PROJECT_TYPES](https://github.com/CycloneDX/cdxgen/blob/v12.7.0/docs/PROJECT_TYPES.md#L28-L29),
  [src](https://github.com/CycloneDX/cdxgen/blob/v12.7.0/lib/cli/index.js#L4999-L5068)).

### JavaScript / TypeScript

- Full-graph lockfiles: syft reads `package-lock.json`, `yarn.lock`,
  `pnpm-lock.yaml`, `bun.lock`, and `deno.lock`; trivy reads
  `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, and `bun.lock`; cdxgen
  reads `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, and
  `pnpm-lock.yaml`.
- `package.json`: syft has it off by default on `dir:` scans (the cataloger
  lacks the `directory` tag), but `--override-default-catalogers all` turns it
  on; trivy reports the project name and version only, not dependencies; cdxgen
  is direct-only and treats it as a primary source only in container mode.
- `bun.lock`: syft parses it; trivy parses the text `bun.lock` (not the binary
  `.lockb`); cdxgen does not parse it at all.
- A bare `package.json` with no lockfile: yields nothing from syft unless the
  override is set; from trivy the name and version only; and from cdxgen unless
  a `node_modules/` is present.
- Sources: syft
  ([cataloger.go](https://github.com/anchore/syft/blob/v1.46.0/syft/pkg/cataloger/javascript/cataloger.go#L11-L30),
  [tags](https://github.com/anchore/syft/blob/v1.46.0/internal/task/package_tasks.go#L77)),
  trivy ([coverage](https://trivy.dev/docs/latest/coverage/language/nodejs/),
  [src](https://github.com/aquasecurity/trivy/blob/v0.72.0/pkg/fanal/analyzer/language/nodejs/pkg/pkg.go)),
  cdxgen
  ([PROJECT_TYPES](https://github.com/CycloneDX/cdxgen/blob/v12.7.0/docs/PROJECT_TYPES.md#L16),
  [src](https://github.com/CycloneDX/cdxgen/blob/v12.7.0/lib/cli/index.js#L4399-L4432)).

## Per-tool details

### syft 1.46.0

- Cataloger tags decide the default set: a `dir:` scan runs catalogers tagged
  `directory`, `--override-default-catalogers` replaces the base set (`all`
  matches every cataloger and bypasses the directory/image restriction), and
  `--select-catalogers` adjusts it with `+`/`-`.
  ([cataloger_selection.go](https://github.com/anchore/syft/blob/v1.46.0/cmd/syft/internal/options/cataloger_selection.go#L34-L38))
- No `pyproject.toml` parser exists (zero source references), so only lockfiles
  give Python dependencies.
  ([cataloger.go](https://github.com/anchore/syft/blob/v1.46.0/syft/pkg/cataloger/python/cataloger.go#L14-L31))
- Unpinned `requirements.txt` entries are dropped unless
  `SYFT_PYTHON_GUESS_UNPINNED_REQUIREMENTS=true`, which infers a version from a
  constraint (`flask>=2.0` becomes `2.0`); a truly bare entry (`requests`, with
  no operator) is dropped even then.
  ([config.go](https://github.com/anchore/syft/blob/v1.46.0/syft/pkg/cataloger/python/config.go#L6-L8),
  [parse_requirements.go](https://github.com/anchore/syft/blob/v1.46.0/syft/pkg/cataloger/python/parse_requirements.go#L140-L197))
- `package.json` is off for `dir:` scans because `javascript-package-cataloger`
  lacks the `directory` tag, and `--override-default-catalogers all` enables it,
  which is a real reason the override can catch extra JS dependencies; a bare
  `package.json` alone otherwise yields nothing.
  ([package_tasks.go](https://github.com/anchore/syft/blob/v1.46.0/internal/task/package_tasks.go#L77))
- For Go, `go.mod` alone yields versioned direct and `// indirect` dependencies,
  `go.sum` only adds hashes, and `vendor/modules.txt` is not parsed
  ([parse_go_mod.go](https://github.com/anchore/syft/blob/v1.46.0/syft/pkg/cataloger/golang/parse_go_mod.go#L41-L46));
  `golang.use-packages-lib` defaults to true and can shell out to `go`
  ([config.go](https://github.com/anchore/syft/blob/v1.46.0/syft/pkg/cataloger/golang/config.go#L52-L53)).
- The configuration knobs are `SYFT_PYTHON_GUESS_UNPINNED_REQUIREMENTS`,
  `--override-default-catalogers`, `--select-catalogers`, `--exclude`, and
  `SYFT_GOLANG_USE_PACKAGES_LIB`, with env mapping `SYFT_<SECTION>_<KEY>`.

### trivy 0.72.0

- trivy is lockfile-centric, driven by its published coverage tables for Python
  ([coverage](https://trivy.dev/docs/latest/coverage/language/python/)), Node.js
  ([coverage](https://trivy.dev/docs/latest/coverage/language/nodejs/)), and Go
  ([coverage](https://trivy.dev/docs/latest/coverage/language/golang/)).
- For `requirements.txt`, only `==` pins are read by default and unversioned
  lines are dropped; `--detection-priority comprehensive` widens this to `>=`,
  `~=`, and similar.
  ([src](https://github.com/aquasecurity/trivy/blob/v0.72.0/pkg/dependency/parser/python/pip/parse.go))
- `pyproject.toml` is not an independent package source, only a companion to
  `poetry.lock`, so a bare `pyproject.toml` yields nothing.
- A `package.json` without a lockfile reports only the project's own name and
  version, not its dependencies.
  ([src](https://github.com/aquasecurity/trivy/blob/v0.72.0/pkg/fanal/analyzer/language/nodejs/pkg/pkg.go))
- Dev dependencies are excluded by default for npm, yarn, pnpm, bun, poetry, and
  uv; `--include-dev-deps` includes them, though its help text understates which
  ecosystems it covers.
  ([coverage](https://trivy.dev/docs/latest/coverage/language/nodejs/))
- For Go, `go.mod` alone is full on Go 1.17 or newer, while `go.sum` is needed
  for indirect dependencies on Go before 1.17.
  ([coverage](https://trivy.dev/docs/latest/coverage/language/golang/))
- The configuration knobs are `--pkg-types` (default `os,library`),
  `--scanners`, `--include-dev-deps` (default false), `--pkg-relationships`, and
  `--detection-priority`.
  ([CLI ref](https://trivy.dev/docs/latest/references/configuration/cli/trivy_filesystem/))

### cdxgen 12.7.0 (`--no-install-deps --lifecycle pre-build`)

- `--lifecycle pre-build` forces `installDeps=false`.
  ([bin/cdxgen.js](https://github.com/CycloneDX/cdxgen/blob/v12.7.0/bin/cdxgen.js#L967-L972))
- `pyproject.toml` dependencies are parsed but discarded without installing,
  because the parsed dependency keys are never turned into components and
  enumeration lives inside the `installDeps` branch
  (`pip install`/`pip freeze`); a bare `pyproject.toml` or `setup.py` therefore
  yields parent metadata only.
  ([src](https://github.com/CycloneDX/cdxgen/blob/v12.7.0/lib/cli/index.js#L4769-L5068),
  [PROJECT_TYPES](https://github.com/CycloneDX/cdxgen/blob/v12.7.0/docs/PROJECT_TYPES.md#L28-L29))
- Python lockfiles (`poetry.lock`, `pdm.lock`, `uv.lock`, `pylock.toml`,
  `Pipfile.lock`) parse statically to a full graph.
- `bun.lock` is not parsed in v12.7.0, which has no parser for it, only an
  audit-report hint.
  ([src](https://github.com/CycloneDX/cdxgen/blob/v12.7.0/lib/helpers/utils.js#L181-L184))
- JS lockfiles (`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`,
  `pnpm-lock.yaml`) parse statically to a full graph, whereas a bare
  `package.json` needs a populated `node_modules/` to yield anything.
  ([src](https://github.com/CycloneDX/cdxgen/blob/v12.7.0/lib/cli/index.js#L4399-L4432))
- The configuration knobs are `--deep`, `--required-only`, `--profile` (some
  profiles re-enable installs), `FETCH_LICENSE`, `USE_GOSUM`,
  `CDXGEN_ALLOWED_COMMANDS`, and `--dry-run`.
  ([ENV.md](https://github.com/CycloneDX/cdxgen/blob/v12.7.0/docs/ENV.md))

## Limits and gaps

If reposcan runs without network access, and the repository does not contain a
handled lockfile, the SBOM and SCA scans may detect only a subset (or none) of
the dependencies. This is also true if reposcan runs with network access and the
repository does not contain a handled manifest.

### cdxgen toolchain execution

`--no-install-deps` is a per-ecosystem opt-in rather than a global no-subprocess
switch. Three un-gated executions are verified in v12.7.0: `go list -deps` and
`go mod graph` run whenever `go` is on PATH
([src](https://github.com/CycloneDX/cdxgen/blob/v12.7.0/lib/cli/index.js#L5466-L5523));
a `Pipfile` triggers `pipenv install`, which runs build backends
([src](https://github.com/CycloneDX/cdxgen/blob/v12.7.0/lib/cli/index.js#L4958-L4972));
and a `rush.json` triggers `rush install`
([src](https://github.com/CycloneDX/cdxgen/blob/v12.7.0/lib/cli/index.js#L4113-L4134)).
For a hard guarantee against executing untrusted repository tooling, layer
`CDXGEN_ALLOWED_COMMANDS` (an allowlist) or `--dry-run`, or strip `go`,
`pipenv`, and `rush` from PATH in the scan environment. reposcan already runs
scans as an unprivileged user, which limits the blast radius but does not stop
these invocations.

# Gitignore support

## Problem

Most of the scanning tools driven by `reposcan` examine a repository by walking
its working tree. Some tools respect `.gitignore`, but many don't, leading to
false-positives.

## Example: SBOM tools

None of the `reposcan`-driven SBOM tools honors `.gitignore` natively. Each has
an open, unmerged feature request. Each offers a manual path-exclusion flag
instead, with a different glob dialect and different anchoring rules.

### syft 1.46.0

- No `.gitignore` support (open, unmerged: anchore/syft#4026, PR #4437).
- Flag: `--exclude <glob>` (repeatable), or `exclude:` list in `.syft.yaml`.
- Dialect: doublestar (`github.com/bmatcuk/doublestar/v4`). Patterns are matched
  against each entry's absolute path, anchored to the `dir:` source root. A
  pattern MUST start with `./`, `*/`, or `**/` (anything else is a hard error).
- `a/**` matches `a` itself as well as its contents, so `**/.venv/**` prunes the
  `.venv` directory (SkipDir) at any depth. No negation (`!`) support
  (anchore/syft#4702).
- Docs: https://oss.anchore.com/docs/guides/sbom/file-selection/ ,
  https://github.com/anchore/syft/wiki/excluding-file-paths

### trivy 0.72.0

- No `.gitignore` support (open: aquasecurity/trivy#3670).
- Flags: `--skip-dirs <glob>`, `--skip-files <glob>` (repeatable), or
  `scan.skip-dirs`/`scan.skip-files` in `trivy.yaml`. Applies to `trivy fs` for
  both the CycloneDX SBOM and the vuln (SCA) scan.
- Dialect: doublestar, matched relative to the scan target / CWD (now the same
  path). Note: `**/.terraform` matches `foo/.terraform` but not `./.terraform`.
- `.trivyignore` is NOT a path filter: it suppresses vulnerability/rule IDs from
  findings after the scan, and has no effect on what gets cataloged. (Maintainer
  confirmation: aquasecurity/trivy discussion #4584.)
- Docs:
  https://github.com/aquasecurity/trivy/blob/v0.72.0/docs/guide/configuration/skipping.md

### cdxgen 12.7.0

- No `.gitignore` support (no gitignore code in the source at all).
- Flag: `--exclude <glob>` (repeatable; not comma-separated). No env-var form.
- Dialect: the `glob`/minimatch family (not picomatch). Globs run with
  `nodir: true`, so patterns must match FILES under a directory: use the
  `**/<name>/**` form (both a depth prefix and a `/**` suffix); bare `**/.venv`
  will not reliably exclude its contents. No negation support.
- Default ignores are only `**/.git/**`, `**/.hg/**`, and (conditionally)
  `**/node_modules/**`. Two root causes of the reported leakage:
  - Python discovery of `site-packages`/`*.whl`/`*.egg-info` runs with
    `includeDot: true`, which deliberately descends into hidden dirs like
    `.venv` and `.tox`.
  - `node_modules` is deliberately walked when the glob targets `package.json`
    (to read installed packages), so it is not always excluded by default. An
    explicit `--exclude` overrides both (excludes are unconditionally appended
    to the ignore list). Do NOT set `CDXGEN_NO_IGNORE` (it disables the default
    ignores).
- Docs: https://github.com/CycloneDX/cdxgen/blob/v12.7.0/docs/ADVANCED.md ,
  https://github.com/CycloneDX/cdxgen/blob/v12.7.0/docs/ENV.md

## reposcan's fix

`reposcan` uses `git` to identify and manually exclude `gitignored` content.

The `git` command:

```
git ls-files -z -o -i --exclude-standard --directory
```

...is run in the repo root to list ignored entries, with wholly-ignored
directories collapsed to `<dir>/`.

The result is used two ways:

### Per-tool exclusion arguments

Each `gitignored` path is mapped to tool flags. For example:

| Tool        | ignored dir `d/`   | ignored file `f` |
| ----------- | ------------------ | ---------------- |
| syft, grype | `--exclude ./d/**` | `--exclude ./f`  |
| trivy       | `--skip-dirs d`    | `--skip-files f` |
| cdxgen      | `--exclude d/**`   | `--exclude f`    |

The flags are then injected into the tool commands.

### Security scan result exclusions

All security scan results are checked against the `gitignored` paths and dropped
if out of scope.

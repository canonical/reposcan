# Generate an SBOM

`reposcan sbom <path>` builds a CycloneDX software bill of materials for a
repository, running trivy, syft, and cdxgen and merging their components into
one de-duplicated inventory. An SBOM is an inventory rather than a pass/fail
check, so the command always exits `0` when it runs.

```
reposcan sbom ./repo
```

Run `reposcan sbom --help` for the option list.

## Output formats

By default reposcan prints a component table to stdout. Override the format with
`--format` and the destination with `-o`:

```
reposcan sbom ./repo                             # table on stdout
reposcan sbom ./repo --format json               # CycloneDX JSON on stdout
reposcan sbom ./repo --format json -o sbom.json
reposcan sbom ./repo --format sqlite -o sbom.db
```

The `sqlite` format is queryable and fully reconstructable, and it requires a
file (`-o`). `-n/--limit` and `--wrap` tune the stdout table, as for `scan`.

## Dependency resolution options

`sbom` supports two dependency resolution options:

- `--include-dev-dependencies`: include development dependencies.
- `--allow-code-execution`: let dependency resolution build source packages when
  a lockfile is absent. This may run untrusted code, so it is off by default.

See also: [SBOM generation](../explanation/sbom-generation.md).

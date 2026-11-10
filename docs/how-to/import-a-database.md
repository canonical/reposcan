# Import a database

`reposcan db import` merges the analyses one reposcan database recorded into
another: for example, a CI job's database into the one a service keeps. How an
import matches issues and orders analyses is explained in
[Architecture](../explanation/architecture.md#output), and every option is in
the [command reference](../reference/commands.md#import).

## Import

```bash
reposcan db import ci-run.db --db history.db --produced-by "github:acme/app#1234"
```

`--produced-by` names where the analyses in `ci-run.db` came from. `history.db`
is created if it does not exist, and `ci-run.db` is only read.

If an import fails part-way, fix the cause and run the same command again: it
picks up where it stopped. Running it again after a successful import changes
nothing.

## Keep raw secrets

The import drops the raw secret values that a secrets scan run with
`--retain-secrets` kept. To keep them, pass `--retain-secrets` to the import
too.

Every other part of a finding is copied exactly as recorded, so restrict access
to the receiving database at least as tightly as to anything imported into it.

## Import from a read-only location

reposcan databases use SQLite's write-ahead log, and SQLite creates a file
beside such a database to read it, even read-only. Copy a database that sits on
a read-only filesystem or mount to a writable directory before importing it.

To ship a database for import, export a copy with SQLite's `VACUUM INTO`. The
copy is consistent even while the original is being written, and it does not use
the write-ahead log, so it can be imported from a read-only location:

```bash
sqlite3 history.db "VACUUM INTO 'export.db'"
```

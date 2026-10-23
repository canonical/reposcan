# Import a database

`reposcan db import` merges the analyses one reposcan database recorded into
another: for example, a CI job's database into the one a service keeps. Issues
known to both databases become one issue, so a finding already triaged in the
receiving database is recognized when it arrives from elsewhere.

## Import

```bash
reposcan db import ci-run.db --db history.db --produced-by "github:acme/app#1234"
```

`--produced-by` names who produced the analyses in `ci-run.db`, and is recorded
with each of them. Analyses that `ci-run.db` had imported from somewhere else
keep the label they already carry. `history.db` is created if it does not exist,
and `ci-run.db` is only read.

## Run it again safely

Every analysis has a unique id, and analyses the receiving database already
holds are skipped. Importing the same database twice changes nothing, and an
import that failed part-way picks up where it stopped when run again: each
analysis is recorded on its own, so the ones before a failure stay recorded.

## Keep raw secrets out of the receiving database

A secrets scan run with `--retain-secrets` keeps each secret's raw value in its
finding. The import drops those values, so the receiving database does not
collect live credentials from every database imported into it. Each finding
still records where the secret is and a hash of it, which is what matches it to
an issue, and the imported database keeps its own copy. To keep the values, pass
`--retain-secrets` to the import too.

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

## What "latest" means afterwards

A database orders analyses by when it recorded them, not by when they ran. An
imported analysis counts as more recent than everything the receiving database
held before it, however old the scan is. See
[Architecture](../explanation/architecture.md#output).

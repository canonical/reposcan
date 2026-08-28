# License compliance

reposcan drives a fixed set of third-party tools, each pinned by hash in
`src/reposcan/tools/registry.py` and listed with its license in the
[README](../../README.md#bundled-tools-and-their-licenses). Every tool remains
under its own upstream license. This page explains how reposcan's use of them
stays within those licenses.

`reposcan` does not modify, fork, or link any of these tools into its own code.
Each is installed from its official upstream release, pinned by hash, and
invoked as a separate, unmodified executable across a process boundary. Running
a program this way is mere aggregation, not the creation of a derivative work,
so no tool's license reaches into `reposcan`'s own source.

- Permissive licenses (Apache-2.0, MIT, BSD-3-Clause) allow use and
  redistribution provided the copyright and license notices are preserved. When
  a built image bundles a tool's binary, that tool's own license and notice
  files are kept alongside it.
- LGPL-2.1 (semgrep): `reposcan` uses semgrep as a standalone program rather
  than linking its library, so it is a plain user of the software. Notices are
  preserved and the corresponding source is the pinned upstream release.
- AGPL-3.0 (trufflehog): the strongest copyleft here. Its obligations attach to
  conveying a modified version, including over a network. `reposcan` runs
  trufflehog unmodified as a separate process and incorporates none of its code,
  so it creates no derivative work. Where a published image redistributes the
  trufflehog binary, AGPL-3.0's source-availability requirement is satisfied by
  the corresponding unmodified upstream source at the pinned release.

Because every tool is pinned by hash to an official upstream release (see the
`# verify:` links in the registry), the exact corresponding source for any
redistributed binary is always identifiable. Local bootstrap, which downloads
each tool from upstream at run time, redistributes nothing; redistribution
obligations (notice retention, source availability) apply only to published
images that bundle the binaries. This summary is provided in good faith and is
not legal advice; consult each linked license for its authoritative terms.

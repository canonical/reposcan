# Ignore false positives

There are two ways to ignore false positives reported by reposcan:

1. Leverage the native suppression methods of the underlying tools
1. Configure a `.reposcan-ignore`

## Native suppression options

reposcan is a scan orchestrator and aggregator. It doesn't produce findings; It
runs third-party scanners and aggregates their findings. Generally, each of the
underlying tools has its own methods for configuring false positive
suppression(s).

For example, zizmor (part of the `workflow` scan) reads `.github/zizmor.yml` and
honours inline `# zizmor: ignore[<rule>]` comments. To stop it flagging an
unpinned reference to a first-party action, either set a policy in config:

```yaml
# .github/zizmor.yml
rules:
  unpinned-uses:
    config:
      policies:
        canonical/repo-scanner: ref-pin # allow a tag/branch, not only a hash
```

or annotate the line:

```yaml
      - uses: canonical/repo-scanner@main # zizmor: ignore[unpinned-uses]
```

Other tools have their own conventions: semgrep honours `# nosemgrep`, checkov
`# checkov:skip=<id>`, and trufflehog a `# trufflehog:ignore` comment on the
finding's line.

## reposcan ignorefile

reposcan supports its own suppression configuration to enable a single,
consolidated ignorefile.

File format:

```
# .reposcan-ignore
#   <tool>  <ruleId>  <path-glob>

# sha256 hashes in hash-pinned requirements trip trufflehog's SentryToken detector
trufflehog  SentryToken  src/repo_scanner/tools/locks/*.txt

# a checkov rule accepted everywhere, whichever tool reported it
*  CKV_AWS_18  **/*.tf
```

- `tool`: the scanner that reported the finding, as shown in the report, or `*`
  for any.
- `ruleId`: the finding's rule id.
- `path-glob`: a repository-root-relative glob. `*` matches within one path
  segment, `**` across segments, and `?` matches a single character.

A finding is dropped if it matches a rule.

By default, reposcan reads `.reposcan-ignore` from the scanned repository. A
custom filepath can be specified with `--ignore-file <path>`. Use of the default
filepath can be toggled off with `--no-ignore-file`.

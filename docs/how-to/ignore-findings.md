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
#   <tool>  <ruleId>  <path-glob>  [content-regex]

# sha256 hashes in hash-pinned requirements trip trufflehog's SentryToken detector
trufflehog  SentryToken  src/repo_scanner/tools/locks/*.txt

# a checkov rule accepted everywhere, whichever tool reported it
*  CKV_AWS_18  **/*.tf

# treat 'trusted-org' as a verified action creator
poutine  github_action_from_unverified_creator_used  .github/workflows/*.yml  "uses: trusted-org/"
```

A finding is dropped if it matches a rule. Each rule has the following fields:

- `tool`: the scanner that reported the finding, as shown in the report, or `*`
  for any.
- `ruleId`: the finding's rule id.
- `path-glob`: a repository-root-relative glob. `*` matches within one path
  segment, `**` across segments, and `?` matches a single character.
- `content-regex` (optional): a regular expression matched against the offending
  content. When given, the finding is dropped only if the regex also matches.
  The content is the finding's line (or the whole file when it has no line). The
  finding is kept if that content cannot be read.

Notes:

- Fields are whitespace-separated.
- A `#` begins a comment.
- Wrap a field in single or double quotes to include whitespace or a `#`.
- Each entry must have exactly three or four fields.

By default, reposcan reads `.reposcan-ignore` from the scanned repository. A
custom filepath can be specified with `--ignore-file <path>`. Use of the default
filepath can be toggled off with `--no-ignore-file`.

# Changelog fragments

One file per change, so parallel pull requests never touch the same lines.

Three PRs merged into 1.3.1 each added a bullet to `## [Unreleased]` in
`CHANGELOG.md`, and each one conflicted with the previous — the same few lines, three
rebases. A fragment file cannot conflict with another fragment file.

## Adding an entry

Create `changelog.d/<number>.<category>.md`, where `<number>` is the issue or PR number
and `<category>` is one of `added`, `changed`, `deprecated`, `removed`, `fixed`,
`security` (the Keep a Changelog sections, in that order).

The file holds the entry text without the leading `- `. Write it the way the existing
CHANGELOG reads: what changed, what it was before, and why it matters. Markdown is
allowed; keep it to one paragraph.

```
$ cat changelog.d/969.fixed.md
**PyPI simple JSON no longer stats every file (#969)** — the PEP 700 fields added in
#963 cost one storage `stat()` per file in the index …
```

## Assembling

`scripts/changelog-fragments.sh` reads the directory and writes the result:

```
./scripts/changelog-fragments.sh --check      # fragments are well-formed
./scripts/changelog-fragments.sh --render     # print the assembled section
./scripts/changelog-fragments.sh --apply      # write it into ## [Unreleased]
./scripts/changelog-fragments.sh --release 1.3.1   # promote to a version section and delete the fragments
```

`--apply` and `--release` are the only modes that touch `CHANGELOG.md`; the file stays
the released artifact and `scripts/verify-changelog.sh` keeps checking it.

#!/usr/bin/env bash
# Build the GitHub GraphQL `createCommitOnBranch` FileChanges object from the
# currently staged tree (the result of `git merge --squash <pr-head>` in
# auto-reland.yml) and write it as JSON to $1.
#
# Why a script instead of inline YAML: file contents are streamed through temp
# files and read into jq with --rawfile / --slurpfile, NEVER passed as
# command-line arguments. The previous inline builder did
# `jq --arg c "$base64_of_whole_file"`, and a single argv string is capped at
# MAX_ARG_STRLEN (128 KiB on Linux); a large PR (the RPM registry, #825) blew
# past it with "Argument list too long" and the reland failed. Reading from
# files has no such limit.
#
# Exits non-zero on an empty diff: a reland that stages nothing would land an
# empty commit and silently drop the reviewed diff (the #798 incident).
set -euo pipefail

out="${1:?usage: reland-build-filechanges.sh <out.json>}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

: >"$work/additions.jsonl"
: >"$work/deletions.jsonl"

# --no-renames → a rename shows up as delete-old + add-new (simplest correct form).
while IFS=$'\t' read -r status path; do
  case "$status" in
    D)
      # shellcheck disable=SC2016  # $p is a jq variable, not a shell one
      jq -cn --arg p "$path" '{path: $p}' >>"$work/deletions.jsonl"
      ;;
    A | M)
      # base64 to a file (strip the trailing newline base64(1) appends), then
      # read it back with --rawfile so the content never touches argv.
      base64 -w0 "$path" | tr -d '\n' >"$work/b64"
      # shellcheck disable=SC2016  # $p/$c are jq variables, not shell ones
      jq -cn --arg p "$path" --rawfile c "$work/b64" '{path: $p, contents: $c}' \
        >>"$work/additions.jsonl"
      ;;
    *)
      echo "reland-build-filechanges: unexpected status '$status' for '$path'" >&2
      exit 1
      ;;
  esac
done < <(git diff --cached --no-renames --name-status)

if [ ! -s "$work/additions.jsonl" ] && [ ! -s "$work/deletions.jsonl" ]; then
  echo "reland-build-filechanges: empty diff — refusing to build an empty reland (guards #798)" >&2
  exit 2
fi

# --slurpfile reads the newline-delimited objects from each file into an array.
jq -c -n \
  --slurpfile a "$work/additions.jsonl" \
  --slurpfile d "$work/deletions.jsonl" \
  '{additions: $a, deletions: $d}' >"$out"

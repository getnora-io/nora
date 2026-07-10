#!/usr/bin/env bash
# Regression test for scripts/reland-build-filechanges.sh.
#
# Guards the auto-reland ARG_MAX bug (#825): a staged file whose base64 is well
# past MAX_ARG_STRLEN (128 KiB/arg) must still produce a valid FileChanges
# payload that round-trips. If anyone reverts the builder to passing contents
# through `jq --arg`, this test fails with "Argument list too long".
# Also checks the empty-diff guard (#798).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
builder="$here/reland-build-filechanges.sh"

fail() { echo "FAIL: $1" >&2; exit 1; }

# --- large + small file build and round-trip ---------------------------------
repo="$(mktemp -d)"
trap 'rm -rf "$repo"' EXIT
git -C "$repo" init -q
git -C "$repo" config user.email t@example.com
git -C "$repo" config user.name test
git -C "$repo" commit -q --allow-empty -m base

# 512 KiB → base64 ≈ 683 KiB, over 5× the 128 KiB single-arg limit.
head -c 524288 /dev/zero | tr '\0' 'A' >"$repo/big.txt"
printf 'hello\n' >"$repo/small.txt"
git -C "$repo" add big.txt small.txt

out="$repo/fc.json"
( cd "$repo" && "$builder" "$out" ) || fail "builder errored on a large staged file"

jq -e . "$out" >/dev/null || fail "output is not valid JSON"
n=$(jq '.additions | length' "$out")
[ "$n" = 2 ] || fail "expected 2 additions, got $n"
jq -r '.additions[] | select(.path=="big.txt") | .contents' "$out" \
  | base64 -d | cmp -s - "$repo/big.txt" \
  || fail "big.txt content did not round-trip through base64"
echo "PASS: large-file FileChanges builds and round-trips ($(wc -c <"$out") bytes JSON)"

# --- empty diff must be rejected (#798) --------------------------------------
empty="$(mktemp -d)"
git -C "$empty" init -q
git -C "$empty" config user.email t@example.com
git -C "$empty" config user.name test
git -C "$empty" commit -q --allow-empty -m base
if ( cd "$empty" && "$builder" "$empty/fc.json" ) 2>/dev/null; then
  fail "empty diff should have been rejected"
fi
echo "PASS: empty diff rejected (#798 guard)"

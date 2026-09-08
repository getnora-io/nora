#!/usr/bin/env bash
# test-changelog-fragments.sh — self-test for scripts/changelog-fragments.sh.
#
# The assembler is the thing that lets fragments replace hand-edited changelog lines;
# if it drifts, the release notes drift with it. These fixtures pin the shape of the
# output and the malformed-name rejections.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAILURES=0

# Isolated copy of the tool plus a scratch repo layout, so the real tree is untouched.
mkdir -p "$TMP/scripts" "$TMP/changelog.d"
cp "$ROOT/scripts/changelog-fragments.sh" "$TMP/scripts/"
printf '# Changelog\n## [Unreleased]\n\n## [1.3.0] - 2026-09-06\n\n### Added\n- old entry\n' > "$TMP/CHANGELOG.md"

check() { # name, expected-rc, description
    local rc=0
    "$TMP/scripts/changelog-fragments.sh" "$1" >"$TMP/out" 2>&1 || rc=$?
    if [ "$rc" = "$2" ]; then
        echo "  OK: $3"
    else
        echo "FAIL: $3 — rc=$rc, expected $2"; sed 's/^/      /' "$TMP/out"; FAILURES=$((FAILURES + 1))
    fi
}

printf '**Second (#20)** — b\n' > "$TMP/changelog.d/20.fixed.md"
printf '**First (#7)** — a\n'   > "$TMP/changelog.d/7.fixed.md"
printf '**A change (#9)** — c\n' > "$TMP/changelog.d/9.changed.md"

check --check 0 "well-formed fragments pass"

"$TMP/scripts/changelog-fragments.sh" --render > "$TMP/rendered"
EXPECTED="### Changed
- **A change (#9)** — c

### Fixed
- **First (#7)** — a
- **Second (#20)** — b"
if [ "$(cat "$TMP/rendered")" = "$EXPECTED" ]; then
    echo "  OK: categories keep Keep-a-Changelog order and entries sort numerically"
else
    echo "FAIL: rendered output does not match"; diff <(echo "$EXPECTED") "$TMP/rendered" | sed 's/^/      /'
    FAILURES=$((FAILURES + 1))
fi

printf 'x\n' > "$TMP/changelog.d/bad-name.md"
check --check 1 "a fragment with a malformed name is rejected"
rm "$TMP/changelog.d/bad-name.md"

printf '%s\n' '- **Leading dash (#3)** — d' > "$TMP/changelog.d/3.fixed.md"
check --check 1 "a fragment that already starts with '- ' is rejected"
rm "$TMP/changelog.d/3.fixed.md"

: > "$TMP/changelog.d/4.fixed.md"
check --check 1 "an empty fragment is rejected"
rm "$TMP/changelog.d/4.fixed.md"

"$TMP/scripts/changelog-fragments.sh" --apply >/dev/null 2>&1
if grep -q "A change (#9)" "$TMP/CHANGELOG.md" && grep -q "^## \[Unreleased\]" "$TMP/CHANGELOG.md"; then
    echo "  OK: --apply writes the section under [Unreleased]"
else
    echo "FAIL: --apply did not write the section"; FAILURES=$((FAILURES + 1))
fi

# --apply must refuse to clobber entries someone wrote by hand.
check --apply 1 "--apply refuses when [Unreleased] already has entries"

"$TMP/scripts/changelog-fragments.sh" --release 1.3.1 >/dev/null 2>&1
LEFT=$(find "$TMP/changelog.d" -name '*.md' ! -name README.md | wc -l)
if grep -q "^## \[1.3.1\] - " "$TMP/CHANGELOG.md" && [ "$LEFT" = "0" ]; then
    echo "  OK: --release dates the section and consumes the fragments"
else
    echo "FAIL: --release left $LEFT fragment(s) or wrote no version heading"; FAILURES=$((FAILURES + 1))
fi

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo "changelog-fragments self-test PASSED"
else
    echo "changelog-fragments self-test FAILED ($FAILURES)"
    exit 1
fi

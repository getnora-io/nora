#!/usr/bin/env bash
# test-lock-audit.sh — self-test for scripts/lock-audit.sh Check 2.
#
# Check 2 is a heuristic over source text, and a heuristic with no test drifts:
# #839 and #971 were both the same check reporting a guard that cannot drop early.
# These two fixtures pin the boundary — a guard that genuinely drops before a write
# on the same path must be reported, and one whose write is on a mutually exclusive
# branch must not.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AUDIT="$ROOT/scripts/lock-audit.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAILURES=0

cat > "$TMP/positive.rs" <<'RS'
// The guard is scoped to an `if` block; the write happens after it closes, on the
// same path. The guard has provably dropped by then — this must be reported.
async fn handler(state: AppState, key: String) -> Response {
    if is_cached(&key) {
        let lock = state.publish_lock(&key);
        let _guard = lock.lock().await;
        let _ = state.storage.get(&key).await;
    }
    let _ = state.storage.put(&key, b"data").await;
    StatusCode::OK.into_response()
}
RS

cat > "$TMP/exclusive.rs" <<'RS'
// The guard sits under `if !is_tarball` and the write under `if is_tarball`. No
// request takes both branches, so the guard is never held on the path that reaches
// the write and cannot drop before it — this must NOT be reported (#971).
async fn handler(state: AppState, key: String, is_tarball: bool) -> Response {
    if !is_tarball {
        if has_versions(&key) {
            let lock = state.publish_lock(&key);
            let _guard = lock.lock().await;
            let _ = state.storage.get(&key).await;
        }
    }
    if is_tarball {
        let _ = state.storage.put(&key, b"data").await;
    }
    StatusCode::OK.into_response()
}
RS

cat > "$TMP/annotated.rs" <<'RS'
// Same shape as positive.rs, but the write carries a documented exemption inside its
// own block — the reason lives next to the code, so the check must stay quiet.
async fn handler(state: AppState, key: String) -> Response {
    if is_cached(&key) {
        let lock = state.publish_lock(&key);
        let _guard = lock.lock().await;
        let _ = state.storage.get(&key).await;
    }
    {
        // LOCK-SAFE: cache-through write to a key nothing else owns; no RMW race
        let _ = state.storage.put(&key, b"data").await;
    }
    StatusCode::OK.into_response()
}
RS

cat > "$TMP/annotated_no_reason.rs" <<'RS'
// A bare marker with no reason must not silence anything — the exemption is the
// written reason, not the keyword.
async fn handler(state: AppState, key: String) -> Response {
    if is_cached(&key) {
        let lock = state.publish_lock(&key);
        let _guard = lock.lock().await;
        let _ = state.storage.get(&key).await;
    }
    {
        // LOCK-SAFE:
        let _ = state.storage.put(&key, b"data").await;
    }
    StatusCode::OK.into_response()
}
RS

cat > "$TMP/annotated_outer.rs" <<'RS'
// The real shape this has to cover: the marker justifies the branch, and the write
// itself sits one level deeper inside a spawned task.
async fn handler(state: AppState, key: String) -> Response {
    if is_cached(&key) {
        let lock = state.publish_lock(&key);
        let _guard = lock.lock().await;
        let _ = state.storage.get(&key).await;
    }
    if should_cache(&key) {
        // LOCK-SAFE: only reached on a branch the guard above never runs on
        tokio::spawn(async move {
            let _ = state.storage.put(&key, b"data").await;
        });
    }
    StatusCode::OK.into_response()
}
RS

OUT="$(bash "$AUDIT" "$TMP" 2>&1)"

expect_reported() {
    if echo "$OUT" | grep -q "$1"; then
        echo "  OK: $2"
    else
        echo "FAIL: $2 — expected a finding for $1"
        FAILURES=$((FAILURES + 1))
    fi
}
expect_silent() {
    if echo "$OUT" | grep -q "$1"; then
        echo "FAIL: $2 — unexpected finding for $1"
        echo "$OUT" | grep "$1"
        FAILURES=$((FAILURES + 1))
    else
        echo "  OK: $2"
    fi
}

echo "=== lock-audit Check 2 self-test ==="
expect_reported "positive.rs" "a guard that drops before a write on the same path is reported"
expect_silent   "exclusive.rs" "a write on a mutually exclusive branch is not reported"
expect_silent   "annotated.rs" "a write with a LOCK-SAFE reason in its block is not reported"
expect_reported "annotated_no_reason.rs" "a bare LOCK-SAFE marker with no reason does not silence"
expect_silent   "annotated_outer.rs" "a LOCK-SAFE reason one block out still covers the write"

# The audit must behave the same on whatever awk the machine has: gawk here, mawk on
# Debian, Ubuntu and the CI images. A gawk-only construct aborts under mawk, and an
# aborted awk prints nothing — which reads exactly like a clean tree, so this compares
# the findings AND checks each run actually produced one.
IMPLS=""
for impl in gawk mawk; do
    command -v "$impl" >/dev/null 2>&1 || continue
    AWK="$impl" bash "$AUDIT" "$TMP" > "$TMP/out.$impl" 2>&1
    IMPLS="$IMPLS $impl"
    if grep -q "positive.rs" "$TMP/out.$impl"; then
        echo "  OK: $impl reports the known finding (the run was not a silent abort)"
    else
        echo "FAIL: $impl produced no finding for positive.rs — likely an aborted awk"
        sed 's/^/      /' "$TMP/out.$impl" | head -5
        FAILURES=$((FAILURES + 1))
    fi
done
if [ -f "$TMP/out.gawk" ] && [ -f "$TMP/out.mawk" ]; then
    if diff -q "$TMP/out.gawk" "$TMP/out.mawk" >/dev/null 2>&1; then
        echo "  OK: gawk and mawk produce identical output"
    else
        echo "FAIL: gawk and mawk disagree"
        diff "$TMP/out.gawk" "$TMP/out.mawk" | sed 's/^/      /' | head -10
        FAILURES=$((FAILURES + 1))
    fi
else
    echo "  OK: only[$IMPLS ] available, cross-implementation comparison skipped"
fi

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo "lock-audit self-test PASSED"
else
    echo "lock-audit self-test FAILED ($FAILURES)"
    exit 1
fi

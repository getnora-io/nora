#!/usr/bin/env bash
# Rust anti-pattern detection — automated Rust idiom linting (RI-12..RI-21)
# Catches: legacy crates, blocking-in-async, stringly-typed errors, fire-and-forget
# Runs in CI (<5s, no dependencies beyond bash+grep+awk)
#
# RATCHET MECHANISM: budgets are ceilings, not targets.
# Every refactoring PR that reduces a count MUST lower the budget in the same commit.
# The "tighten" section at the end warns when a budget can be lowered.

set -eu
# Note: intentionally no pipefail — grep returns 1 on zero matches,
# which would kill pipe chains like `grep ... | grep -v ... | wc -l`.

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$REPO_ROOT/nora-registry/src"
ERRORS=0
WARNINGS=0

fail() { echo "FAIL: $1"; ERRORS=$((ERRORS + 1)); }
warn() { echo "WARN: $1"; WARNINGS=$((WARNINGS + 1)); }
ok()   { echo "  OK: $1"; }

# Ratchet: if actual is well below budget, enforce tightening.
# gap ≥ 2 → FAIL. Forces every refactoring PR to lower the budget.
ratchet() {
    local name="$1" actual="$2" budget="$3"
    local gap=$((budget - actual))
    if [ "$gap" -ge 2 ]; then
        fail "ratchet: ${name} — actual ${actual}, budget ${budget}. Lower budget to $((actual + 1)) in this PR."
    fi
}

# Helper: count grep hits in non-test production code
count_prod() {
    local pattern="$1"
    local extra="${2:-}"
    if [ -n "$extra" ]; then
        grep -rn "$pattern" "$SRC" --include="*.rs" $extra 2>/dev/null \
            | grep -v '#\[cfg(test)\]' \
            | grep -v '#\[test\]' \
            | grep -v 'mod tests' \
            | grep -v '// test' \
            | wc -l
    else
        grep -rn "$pattern" "$SRC" --include="*.rs" 2>/dev/null \
            | grep -v '#\[cfg(test)\]' \
            | grep -v '#\[test\]' \
            | grep -v 'mod tests' \
            | grep -v '// test' \
            | wc -l
    fi
}

# Helper: list files matching pattern (for diagnostics)
list_hits() {
    local pattern="$1"
    grep -rn "$pattern" "$SRC" --include="*.rs" 2>/dev/null \
        | grep -v '#\[cfg(test)\]' \
        | grep -v '#\[test\]' \
        | grep -v 'mod tests' \
        | sed "s|$REPO_ROOT/||"
}

echo "=== NORA Rust Anti-Pattern Check ==="
echo ""

# ── RI-12. Legacy crates: lazy_static when OnceLock available (MSRV 1.75) ──

echo "--- RI-12: legacy crates (lazy_static) ---"
LAZY_COUNT=$(count_prod 'lazy_static!')
LAZY_BUDGET=4  # Baseline: metrics.rs, gc.rs, retention.rs, config.rs (test). See #480.

if [ "$LAZY_COUNT" -le "$LAZY_BUDGET" ]; then
    ok "lazy_static!: $LAZY_COUNT (budget: $LAZY_BUDGET)"
else
    fail "lazy_static!: $LAZY_COUNT exceeds budget $LAZY_BUDGET — use std::sync::OnceLock instead"
    list_hits 'lazy_static!' | head -5
fi
ratchet "RI-12 lazy_static" "$LAZY_COUNT" "$LAZY_BUDGET"
echo ""

# ── RI-13. Fire-and-forget tokio::spawn without catch_unwind ────────────────
# spawn_cache uses catch_unwind — raw tokio::spawn does not.
# Panics in detached tasks are silently swallowed by tokio.

echo "--- RI-13: fire-and-forget tokio::spawn ---"
# Count raw tokio::spawn that are not:
# - spawn_cache/spawn_blocking (safe wrappers)
# - handles.push / let _ = / let handle = (JoinHandle tracked)
# - catch_unwind (panic-safe)
# - comments (// tokio::spawn)
RAW_SPAWN=$(grep -rn 'tokio::spawn' "$SRC" --include="*.rs" 2>/dev/null \
    | grep -v 'spawn_cache\|spawn_blocking\|catch_unwind' \
    | grep -v 'JoinHandle\|handles\.push\|let.*=.*tokio::spawn' \
    | grep -v '#\[cfg(test)\]\|mod tests\|// .*tokio::spawn\|/// ' \
    | wc -l)
RAW_SPAWN_BUDGET=20  # Baseline: registry handlers + gc/retention schedulers. See #479.

if [ "$RAW_SPAWN" -le "$RAW_SPAWN_BUDGET" ]; then
    ok "raw tokio::spawn (no catch_unwind): $RAW_SPAWN (budget: $RAW_SPAWN_BUDGET)"
else
    fail "raw tokio::spawn: $RAW_SPAWN exceeds budget $RAW_SPAWN_BUDGET — use spawn_cache or track JoinHandle"
    grep -rn 'tokio::spawn' "$SRC" --include="*.rs" 2>/dev/null \
        | grep -v 'spawn_cache\|spawn_blocking\|JoinHandle\|handles\.push\|let.*=.*tokio::spawn' \
        | grep -v '#\[cfg(test)\]\|mod tests' \
        | sed "s|$REPO_ROOT/||" | head -5
fi
ratchet "RI-13 raw_spawn" "$RAW_SPAWN" "$RAW_SPAWN_BUDGET"
echo ""

# ── RI-15. parking_lot::Mutex::lock() in async functions ────────────────────
# parking_lot::Mutex blocks the tokio worker thread. Short holds are OK,
# but growing usage is a latency risk under concurrency.

echo "--- RI-15: blocking lock() in async code ---"
# Find .lock() calls that are NOT .lock().await (sync vs async)
BLOCKING_LOCK=$(grep -rn '\.lock()' "$SRC" --include="*.rs" 2>/dev/null \
    | grep -v '\.lock()\.await\|\.lock()\.unwrap()\|#\[cfg(test)\]\|mod tests' \
    | grep -v '_test\|_spec' \
    | wc -l)
BLOCKING_LOCK_BUDGET=8  # Baseline: auth.rs entries, publish_locks, audit writer

if [ "$BLOCKING_LOCK" -le "$BLOCKING_LOCK_BUDGET" ]; then
    ok "sync .lock() in prod code: $BLOCKING_LOCK (budget: $BLOCKING_LOCK_BUDGET)"
else
    fail "sync .lock(): $BLOCKING_LOCK exceeds budget $BLOCKING_LOCK_BUDGET — prefer tokio::sync::Mutex in async"
    grep -rn '\.lock()' "$SRC" --include="*.rs" 2>/dev/null \
        | grep -v '\.lock()\.await\|\.lock()\.unwrap()\|#\[cfg(test)\]\|mod tests' \
        | sed "s|$REPO_ROOT/||" | head -5
fi
ratchet "RI-15 blocking_lock" "$BLOCKING_LOCK" "$BLOCKING_LOCK_BUDGET"
echo ""

# ── RI-17. Stringly-typed errors: Result<_, String> and Result<_, ()> ───────

echo "--- RI-17: stringly-typed errors ---"
STRING_ERR=$(grep -rn 'Result<.*,\s*String>' "$SRC" --include="*.rs" 2>/dev/null \
    | grep -v '#\[cfg(test)\]\|mod tests\|// test' \
    | wc -l)
UNIT_ERR=$(grep -rn 'Result<.*,\s*()>' "$SRC" --include="*.rs" 2>/dev/null \
    | grep -v '#\[cfg(test)\]\|mod tests\|// test' \
    | wc -l)
STRING_ERR_BUDGET=25  # Baseline: mirror/, backup, oidc, config
UNIT_ERR_BUDGET=6     # Baseline: rewrite fns in pub_dart, npm, go. See #481.

if [ "$STRING_ERR" -le "$STRING_ERR_BUDGET" ]; then
    ok "Result<_, String>: $STRING_ERR (budget: $STRING_ERR_BUDGET)"
else
    fail "Result<_, String>: $STRING_ERR exceeds budget $STRING_ERR_BUDGET — use typed errors"
    grep -rn 'Result<.*,\s*String>' "$SRC" --include="*.rs" 2>/dev/null \
        | grep -v '#\[cfg(test)\]\|mod tests' \
        | sed "s|$REPO_ROOT/||" | head -5
fi
ratchet "RI-17 Result<_,String>" "$STRING_ERR" "$STRING_ERR_BUDGET"

if [ "$UNIT_ERR" -le "$UNIT_ERR_BUDGET" ]; then
    ok "Result<_, ()>: $UNIT_ERR (budget: $UNIT_ERR_BUDGET)"
else
    fail "Result<_, ()>: $UNIT_ERR exceeds budget $UNIT_ERR_BUDGET — use typed errors"
    grep -rn 'Result<.*,\s*()>' "$SRC" --include="*.rs" 2>/dev/null \
        | grep -v '#\[cfg(test)\]\|mod tests' \
        | sed "s|$REPO_ROOT/||" | head -5
fi
ratchet "RI-17 Result<_,()>" "$UNIT_ERR" "$UNIT_ERR_BUDGET"
echo ""

# ── RI-18. #[allow(clippy::*)] budget (excluding unwrap_used in tests) ──────

echo "--- RI-18: clippy allow budget ---"
# Non-unwrap allows in production code (too_many_arguments, result_unit_err, etc.)
CLIPPY_ALLOW_PROD=$(grep -rn '#\[allow(clippy::' "$SRC" --include="*.rs" 2>/dev/null \
    | grep -v 'unwrap_used' \
    | wc -l)
CLIPPY_ALLOW_BUDGET=7  # Current: 6. Headroom: 1.

if [ "$CLIPPY_ALLOW_PROD" -le "$CLIPPY_ALLOW_BUDGET" ]; then
    ok "non-unwrap #[allow(clippy::*)]: $CLIPPY_ALLOW_PROD (budget: $CLIPPY_ALLOW_BUDGET)"
else
    fail "non-unwrap #[allow(clippy::*)]: $CLIPPY_ALLOW_PROD exceeds budget $CLIPPY_ALLOW_BUDGET — fix or justify"
    grep -rn '#\[allow(clippy::' "$SRC" --include="*.rs" 2>/dev/null \
        | grep -v 'unwrap_used' \
        | sed "s|$REPO_ROOT/||" | head -10
fi
ratchet "RI-18 clippy_allows" "$CLIPPY_ALLOW_PROD" "$CLIPPY_ALLOW_BUDGET"
echo ""

# ── RI-19. Error context erasure: .map_err(|e| e.to_string()) ──────────────

echo "--- RI-19: error context erasure ---"
MAP_ERR_TOSTRING=$(grep -rn '\.map_err(|.*|.*\.to_string())' "$SRC" --include="*.rs" 2>/dev/null \
    | grep -v '#\[cfg(test)\]\|mod tests' \
    | wc -l)
MAP_ERR_DISCARD=$(grep -rn '\.map_err(|_|' "$SRC" --include="*.rs" 2>/dev/null \
    | grep -v '#\[cfg(test)\]\|mod tests' \
    | wc -l)
ERASURE_TOTAL=$((MAP_ERR_TOSTRING + MAP_ERR_DISCARD))
ERASURE_BUDGET=33  # Current: 32. Headroom: 1.

if [ "$ERASURE_TOTAL" -le "$ERASURE_BUDGET" ]; then
    ok "error erasure (.map_err to_string + discard): $ERASURE_TOTAL (budget: $ERASURE_BUDGET)"
else
    fail "error erasure: $ERASURE_TOTAL exceeds budget $ERASURE_BUDGET — preserve error context"
    grep -rn '\.map_err(|_|' "$SRC" --include="*.rs" 2>/dev/null \
        | grep -v '#\[cfg(test)\]\|mod tests' \
        | sed "s|$REPO_ROOT/||" | head -5
fi
ratchet "RI-19 error_erasure" "$ERASURE_TOTAL" "$ERASURE_BUDGET"
echo ""

# ── RI-20. Global mutable state: static + Mutex/RwLock ─────────────────────

echo "--- RI-20: global mutable state ---"
GLOBAL_MUT=$(grep -rn '^static\|^pub static\|^pub(crate) static' "$SRC" --include="*.rs" 2>/dev/null \
    | grep -iE 'Mutex|RwLock' \
    | grep -v '#\[cfg(test)\]\|mod tests' \
    | wc -l)
GLOBAL_MUT_BUDGET=0  # Clean baseline — keep it at 0

if [ "$GLOBAL_MUT" -le "$GLOBAL_MUT_BUDGET" ]; then
    ok "global mutable static (Mutex/RwLock): $GLOBAL_MUT (budget: $GLOBAL_MUT_BUDGET)"
else
    fail "global mutable state: $GLOBAL_MUT exceeds budget $GLOBAL_MUT_BUDGET — use AppState instead"
    grep -rn '^static\|^pub static\|^pub(crate) static' "$SRC" --include="*.rs" 2>/dev/null \
        | grep -iE 'Mutex|RwLock' \
        | grep -v '#\[cfg(test)\]\|mod tests' \
        | sed "s|$REPO_ROOT/||"
fi
echo ""

# ── RI-21. God objects: structs with >15 pub fields ─────────────────────────
# Known exceptions: Translations (i18n data struct — one field per UI string)
# Known tracked: Config (#484), CurationConfig (#484), AppState (#483)

echo "--- RI-21: god objects (struct > 15 pub fields) ---"
GOD_OBJECTS=0
GOD_THRESHOLD=15
GOD_BUDGET=3  # Baseline: Config, CurationConfig, AppState. See #483, #484.
# i18n structs are data containers, not god objects
GOD_EXCEPTIONS="Translations"

# Scan for pub structs and count their pub fields
while IFS=: read -r file line content; do
    struct_name=$(echo "$content" | grep -oP 'pub struct \K\w+' || true)
    [ -z "$struct_name" ] && continue

    # Skip known i18n/data exceptions
    echo "$GOD_EXCEPTIONS" | grep -qw "$struct_name" && continue

    # Extract struct body and count pub fields
    pub_count=$(awk -v start="$line" '
        NR >= start { depth += gsub(/{/, "{"); depth -= gsub(/}/, "}") }
        NR > start && depth <= 0 { exit }
        NR >= start && /pub / && !/pub struct/ && !/pub fn/ && !/pub async/ { count++ }
        END { print count+0 }
    ' "$file")

    if [ "$pub_count" -gt "$GOD_THRESHOLD" ]; then
        rel_file=$(echo "$file" | sed "s|$REPO_ROOT/||")
        warn "god object: $struct_name has $pub_count pub fields ($rel_file:$line)"
        GOD_OBJECTS=$((GOD_OBJECTS + 1))
    fi
done < <(grep -rn 'pub struct ' "$SRC" --include="*.rs" 2>/dev/null \
    | grep -v '#\[cfg(test)\]\|mod tests')

if [ "$GOD_OBJECTS" -le "$GOD_BUDGET" ]; then
    ok "god objects (>$GOD_THRESHOLD pub fields): $GOD_OBJECTS (budget: $GOD_BUDGET)"
else
    fail "god objects: $GOD_OBJECTS exceeds budget $GOD_BUDGET — decompose into sub-structs"
fi
echo ""

# ── Summary ─────────────────────────────────────────────────────────────────

echo "=== Results ==="
echo "Errors:   $ERRORS"
echo "Warnings: $WARNINGS"
echo ""

if [ "$ERRORS" -gt 0 ]; then
    echo "Anti-pattern check FAILED with $ERRORS error(s)."
    echo "Fix violations or update budgets in scripts/rust-antipatterns.sh with justification."
    exit 1
fi

if [ "$WARNINGS" -gt 0 ]; then
    echo "Anti-pattern check PASSED with $WARNINGS warning(s)."
else
    echo "Anti-pattern check PASSED."
fi
exit 0

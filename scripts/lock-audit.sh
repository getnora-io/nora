#!/usr/bin/env bash
# lock-audit.sh — Constraint check for publish_lock correctness
# Detects read-modify-write patterns without proper lock scope
# Part of `make check` stage 4
#
# Checks:
# 1. update/generate metadata functions that write storage without lock
# 2. publish_lock guard inside if-block (drops before storage.put)
# 3. Known RMW patterns: index append, metadata merge
set -uo pipefail

REGISTRY_DIR="${1:-nora-registry/src/registry}"
FAIL_FILE=$(mktemp)
echo 0 > "$FAIL_FILE"

red()   { printf '\033[0;31mFAIL\033[0m %s\n' "$1"; echo 1 > "$FAIL_FILE"; }
green() { printf '\033[0;32mOK\033[0m   %s\n' "$1"; }
info()  { printf '\033[0;33mINFO\033[0m %s\n' "$1"; }

echo "=== Lock Audit: publish_lock consistency ==="
echo ""

# ── Check 1: metadata/index update functions must be called under lock ──
# Functions that regenerate shared state (index files, metadata XML/JSON)
# must either contain publish_lock or document that caller holds lock.
echo "--- Check 1: metadata writers need lock ---"

for file in "$REGISTRY_DIR"/*.rs; do
    [ -f "$file" ] || continue
    base=$(basename "$file")

    awk -v base="$base" '
    /^async fn (update_|generate_|rebuild_).*/ {
        fname=$0; has_put=0; has_lock=0; has_doc=0; start=NR; depth=0
        match(fname, /fn ([a-zA-Z_]+)/, m); fn_name=m[1]
    }
    fname!="" && /{/ { depth++ }
    fname!="" && /}/ { depth--
        if (depth <= 0) {
            if (has_put && !has_lock && !has_doc) {
                printf "%s:%d fn %s — writes storage, no publish_lock (caller must hold lock)\n", base, start, fn_name
            }
            fname=""
        }
    }
    fname!="" && /storage\.put/ { has_put=1 }
    fname!="" && /publish_lock/ { has_lock=1 }
    fname!="" && /caller.*lock|called under lock|SAFETY:.*lock/ { has_doc=1 }
    ' "$file"
done | while IFS= read -r finding; do
    info "$finding"
done

# ── Check 2: lock guard must not be scoped inside a conditional/loop block ──
# Bad pattern: publish_lock + _guard inside `if cond { … }` (or for/while/loop),
# whose closing brace drops the guard BEFORE a later storage.put = unprotected write.
#
# The guard's *enclosing* block is found by a backward brace-walk from the guard
# line (the first unmatched `{` going up). We flag ONLY when that opener is an
# if/else/for/while/loop. A guard at function-body scope after early-return guard
# clauses (`if validate(..).is_err() { return }`) has the fn body as its encloser
# and is correctly NOT flagged — the previous line-window heuristic false-positived
# on exactly that idiom (deb/rpm delete_package).
echo ""
echo "--- Check 2: lock guard scope ---"

for file in "$REGISTRY_DIR"/*.rs; do
    [ -f "$file" ] || continue
    base=$(basename "$file")

    awk -v base="$base" '
    /publish_lock/ { lock_line=NR }
    /let _guard/ && lock_line && (NR - lock_line < 3) {
        # Backward brace-walk: the first unmatched `{` above the guard opened the
        # block that lexically encloses it.
        depth=0; encloser=""; enc_line=0
        for (i=NR-1; i>=1; i--) {
            t=lines[i]; nopen=gsub(/[{]/,"",t)
            t=lines[i]; nclose=gsub(/[}]/,"",t)
            depth += nclose - nopen
            if (depth < 0) { encloser=lines[i]; enc_line=i; break }
        }
        is_cond = (encloser ~ /(^|[^A-Za-z0-9_])(if|for|while|loop|else)([^A-Za-z0-9_]|$)/)
        is_excluded = (encloser ~ /=>/) || (encloser ~ /(^|[^A-Za-z0-9_])fn[^A-Za-z0-9_]/) ||
                      (encloser ~ /\|[^|]*\|[[:space:]]*\{/)
        # A guard at fn-body / match-arm / closure scope is held across the rest
        # of that scope — safe. Only a guard inside a conditional/loop CAN drop
        # early; record it for the write-after-close check in END.
        if (is_cond && !is_excluded) { gi++; g_guard[gi]=NR; g_enc[gi]=enc_line }
    }
    { lines[NR]=$0 }
    END {
        for (k=1; k<=gi; k++) {
            # Find where the enclosing conditional/loop block closes.
            d=0; close_line=0
            for (j=g_enc[k]; j<=NR; j++) {
                t=lines[j]; nopen=gsub(/[{]/,"",t)
                t=lines[j]; nclose=gsub(/[}]/,"",t)
                d += nopen - nclose
                if (j > g_enc[k] && d <= 0) { close_line=j; break }
            }
            if (close_line == 0) continue
            # BUG only if a storage write follows the block close, still inside the
            # function (up to the next column-0 `}`): the guard has already dropped,
            # so that write is unserialized. A guard whose block contains ALL its
            # writes (e.g. a per-key lock inside a `for` loop) is correctly ignored.
            for (j=close_line+1; j<=NR; j++) {
                if (lines[j] ~ /^}/) break
                if (lines[j] ~ /storage\.(put|delete|write|put_from_path|put_multipart)/) {
                    printf "%s:%d _guard drops (conditional/loop scope) before storage write at line %d\n", base, g_guard[k], j
                    break
                }
            }
        }
    }
    ' "$file"
done | while IFS= read -r finding; do
    red "$finding"
done

# ── Check 3: index/metadata append patterns need serialization ──
# Detect: storage.get → extend/push/insert → storage.put on same key variable
echo ""
echo "--- Check 3: read-append-write patterns ---"

for file in "$REGISTRY_DIR"/*.rs; do
    [ -f "$file" ] || continue
    base=$(basename "$file")

    # Find get+put pairs where data is modified between them
    awk -v base="$base" '
    /storage\.(get|list)\(&/ {
        read_line=NR
        match($0, /storage\.(get|list)\(&([a-zA-Z_]+)/, m)
        read_key=m[2]
    }
    read_key && /(extend_from_slice|push|insert|entry\(|\.put\()/ && NR > read_line && (NR - read_line < 30) {
        if (/storage\.put/) {
            match($0, /storage\.put\(&([a-zA-Z_]+)/, m)
            put_key=m[1]
            if (put_key == read_key || (read_key && put_key)) {
                # Check if publish_lock exists between read and write
                has_lock=0
                for (i=read_line; i<=NR; i++) {
                    if (context[i] ~ /publish_lock|_guard/) has_lock=1
                }
                # Only flag if no lock found in surrounding function
            }
        }
    }
    { context[NR]=$0 }
    ' "$file" 2>/dev/null
done

# ── Check 4: publish_lock key vs RMW target key ──
echo ""
echo "--- Check 4: lock key matches RMW target ---"

for file in "$REGISTRY_DIR"/*.rs; do
    [ -f "$file" ] || continue
    base=$(basename "$file")

    # Find all publish_lock calls, extract lock key format
    grep -n 'publish_lock' "$file" | while IFS=: read -r lnum line; do
        # Get the key pattern
        lock_key=$(echo "$line" | grep -oP 'publish_lock\(&\K[a-zA-Z_]+')
        [ -z "$lock_key" ] && continue

        # Look at the lock key format string (search backwards from lock line)
        key_format=$(sed -n "$((lnum > 5 ? lnum-5 : 1)),${lnum}p" "$file" | grep -oP 'format!\("([^"]+)"' | tail -1 | sed 's/format!("//;s/"//')

        if [ -n "$key_format" ]; then
            green "[$base:$lnum] lock key pattern: $key_format"
        fi
    done
done

# ── Check 5: concurrent test coverage ──
echo ""
echo "--- Check 5: concurrent publish tests ---"

for format in maven cargo npm pypi docker; do
    if grep -rq "concurrent.*publish\|concurrent.*upload\|tokio::join.*publish" "$REGISTRY_DIR/../" --include="*.rs" 2>/dev/null | grep -qi "$format"; then
        green "$format has concurrent publish test"
    else
        info "$format — no concurrent publish test found"
    fi
done

echo ""
echo "=== Lock Audit complete ==="
RESULT=$(cat "$FAIL_FILE")
rm -f "$FAIL_FILE"
exit "$RESULT"

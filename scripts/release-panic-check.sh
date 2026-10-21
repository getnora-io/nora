#!/usr/bin/env bash
# Copyright (c) 2026 The NORA Authors
# SPDX-License-Identifier: MIT
#
# What a panic does to a release binary (C67, R2-49). Tests always build with unwind,
# whatever the release profile says, so this builds the release profile with the
# `fault-injection` feature and makes the running server panic:
#   handler       GET /__fi/panic       -> 500, the process keeps serving
#   background    GET /__fi/panic-bg    -> an unguarded spawned task panics, the process lives
#   maintenance   GET /__fi/panic-maint-once -> one maintenance tick panics, the loop goes on
#                                          (/health stays 200 past the allowed silence)
#   persistent    GET /__fi/panic-maint -> every tick panics: the loop runs on, but no tick
#                                          completes, so /health turns 503
#   stall         GET /__fi/hang-maint  -> the maintenance loop hangs, /health turns 503
#
# Usage: scripts/release-panic-check.sh            build and check (exit 0 = all hold)
#        PANIC_STRATEGY=abort scripts/...          the same binary built with panic=abort:
#                                                  the check must fail (its RED control)
#        NORA_BIN=/path/to/nora scripts/...        check a binary built elsewhere (with the
#                                                  feature), skipping the build
set -euo pipefail
cd "$(dirname "$0")/.."

PANIC_STRATEGY=${PANIC_STRATEGY:-unwind}
TICK=30          # the maintenance cadence in main.rs
SILENCE=40       # NORA_FI_MAINTENANCE_MAX_SILENCE_SECS for the check

if [ -z "${NORA_BIN:-}" ]; then
  target=${CARGO_TARGET_DIR:-target}/release-panic-check-$PANIC_STRATEGY
  CARGO_TARGET_DIR=$target cargo build --release --locked -p nora-registry \
    --features fault-injection --config "profile.release.panic=\"$PANIC_STRATEGY\""
  NORA_BIN=$target/release/nora
  built=$PANIC_STRATEGY
fi
echo "binary: $NORA_BIN (panic=${built:-prebuilt, profile unknown})"

work=$(mktemp -d)
pid=
cleanup() { [ -n "$pid" ] && kill "$pid" 2>/dev/null; rm -rf "$work"; }
trap cleanup EXIT
export NO_PROXY=127.0.0.1 no_proxy=127.0.0.1

port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
url=http://127.0.0.1:$port
code() { curl -s -m 5 -o /dev/null -w '%{http_code}' "$url$1" || true; }
alive() { kill -0 "$pid" 2>/dev/null; }

start() {
  local dir=$work/$1
  mkdir -p "$dir"
  NORA_HOST=127.0.0.1 NORA_PORT=$port NORA_PUBLIC_URL=$url NORA_STORAGE_PATH=$dir/data \
    NORA_FI_MAINTENANCE_MAX_SILENCE_SECS=$SILENCE "$NORA_BIN" serve > "$dir/nora.log" 2>&1 &
  pid=$!
  for _ in $(seq 1 100); do [ "$(code /health)" = 200 ] && return 0; sleep 0.1; done
  echo "server did not start"; cat "$dir/nora.log"; exit 2
}
stop() { kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; pid=; }

failed=0
verdict() { # name, holds (yes|no), detail
  if [ "$2" = yes ]; then echo "PASS $1: $3"; else echo "FAIL $1: $3"; failed=1; fi
}
holds() { if "$@"; then echo yes; else echo no; fi; }

start handler
c=$(code /__fi/panic); sleep 1
alive && h=$(code /health) || h=dead
verdict handler "$(holds test "$c" = 500 -a "$h" = 200)" "panic answered $c, then /health $h"
stop

start background
curl -s -m 5 -o "$work/bg-body" "$url/__fi/panic-bg" || true; sleep 1
alive && h=$(code /health) || h=dead
verdict background "$(holds test "$h" = 200)" "panic-bg answered $(cat "$work/bg-body" 2>/dev/null), then /health $h"
stop

start maintenance
code /__fi/panic-maint-once >/dev/null
sleep $((TICK + SILENCE + 5))
alive && h=$(code /health) || h=dead
n=$(grep -c 'maintenance tick panicked' "$work/maintenance/nora.log" || true)
verdict maintenance "$(holds test "$h" = 200 -a "$n" = 1)" \
  "/health $h after $((TICK + SILENCE + 5)) s, $n tick panicked"
stop

start persistent
code /__fi/panic-maint >/dev/null
h=200
for _ in $(seq 1 $((TICK + SILENCE + 15))); do
  alive || { h=dead; break; }
  h=$(code /health); [ "$h" = 503 ] && break; sleep 1
done
n=$(grep -c 'maintenance tick panicked' "$work/persistent/nora.log" || true)
verdict persistent "$(holds test "$h" = 503 -a "$n" -ge 1)" "/health $h, $n ticks panicked, process alive"
stop

start stall
code /__fi/hang-maint >/dev/null
h=200
for _ in $(seq 1 $((TICK + SILENCE + 15))); do
  alive || { h=dead; break; }
  h=$(code /health); [ "$h" = 503 ] && break; sleep 1
done
r=$(code /ready)
verdict stall "$(holds test "$h" = 503)" "/health $h, /ready $r once the loop hung"
stop

exit $failed

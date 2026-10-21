#!/usr/bin/env bash
# Copyright (c) 2026 The NORA Authors
# SPDX-License-Identifier: MIT
#
# What a panic does to a release binary (C67, R2-49, supervised tasks). Tests always build
# with unwind, whatever the release profile says, so this builds the release profile with
# the `fault-injection` feature and makes the running server panic:
#   handler       GET /__fi/panic            -> 500, the process keeps serving
#   background    GET /__fi/panic-bg         -> an unguarded spawned task panics, the process lives
#   maintenance   GET /__fi/panic-maint-once -> one maintenance tick panics: the loop is restarted
#                                               and /health stays 200 past the allowed silence
#   persistent    GET /__fi/panic-maint      -> every tick panics: /health turns 503, naming the task
#   stall         GET /__fi/hang-maint       -> the maintenance loop hangs, /health turns 503
#   pull_stats, cleanup, sighup
#                 GET /__fi/panic-task/<t>   -> the task panics once: logged, counted in
#                                               nora_task_panics_total, restarted; /health 200
#                                               (sighup: a SIGHUP after the restart still reloads)
#   crash loop    GET /__fi/panic-task/pull_stats?every=true -> /health 503 naming the task
#   audit         GET /__fi/panic-task/audit -> the audit writer panics: the process exits 70
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

start() { # name [VAR=value...]
  local dir=$work/$1
  shift
  mkdir -p "$dir"
  env NORA_HOST=127.0.0.1 NORA_PORT=$port NORA_PUBLIC_URL=$url NORA_STORAGE_PATH=$dir/data \
    NORA_FI_MAINTENANCE_MAX_SILENCE_SECS=$SILENCE "$@" "$NORA_BIN" serve > "$dir/nora.log" 2>&1 &
  pid=$!
  for _ in $(seq 1 100); do [ "$(code /health)" = 200 ] && return 0; sleep 0.1; done
  echo "server did not start"; cat "$dir/nora.log"; exit 2
}
stop() { kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; pid=; }

# Panics of task $1 in the log of scenario $2, and its counter on /metrics.
panicked() { grep -c "background task panicked.*\"task\":\"$1\"\|\"task\":\"$1\".*background task panicked" "$work/$2/nora.log" || true; }
counted() { curl -s -m 5 "$url/metrics" | awk -v t="nora_task_panics_total{task=\"$1\"}" '$1 == t {print $2}'; }
failing_task() { curl -s -m 5 "$url/health" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("failing_task",""))' 2>/dev/null; }

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
n=$(panicked maintenance maintenance)
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
n=$(panicked maintenance persistent); t=$(failing_task)
verdict persistent "$(holds test "$h" = 503 -a "$n" -ge 1 -a "$t" = maintenance)" \
  "/health $h failing_task=$t, $n ticks panicked, process alive"
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

for task in pull_stats cleanup sighup; do
  start "$task" NORA_GC_ENABLED=true
  a=$(curl -s -m 5 "$url/__fi/panic-task/$task"); sleep 3
  alive && h=$(code /health) || h=dead
  n=$(panicked "$task" "$task"); m=$(counted "$task")
  restarted=$(grep -c "restarting background task.*\"task\":\"$task\"\|\"task\":\"$task\".*restarting background task" "$work/$task/nora.log" || true)
  extra=
  if [ "$task" = sighup ] && [ "$h" = 200 ]; then
    kill -HUP "$pid"; sleep 1
    reloads=$(grep -c 'SIGHUP received' "$work/$task/nora.log" || true)
    extra=" reloads_after_restart=$reloads"
    [ "$reloads" -ge 1 ] || h="$h(no reload)"
  fi
  verdict "$task" "$(holds test "$a" = armed -a "$h" = 200 -a "$n" = 1 -a "$m" = 1 -a "$restarted" -ge 1)" \
    "armed=$a /health $h, logged $n, counted $m, restarted $restarted$extra"
  stop
done

start crash_loop
curl -s -m 5 -o /dev/null "$url/__fi/panic-task/pull_stats?every=true"
h=200
for _ in $(seq 1 60); do
  alive || { h=dead; break; }
  h=$(code /health); [ "$h" = 503 ] && break; sleep 1
done
t=$(failing_task); m=$(counted pull_stats)
verdict crash_loop "$(holds test "$h" = 503 -a "$t" = pull_stats)" \
  "/health $h failing_task=$t, panics counted $m"
stop

start audit
curl -s -m 5 -o /dev/null "$url/__fi/panic-task/audit" || true
rc=alive
for _ in $(seq 1 50); do
  if ! alive; then wait "$pid" && rc=0 || rc=$?; pid=; break; fi
  sleep 0.1
done
n=$(panicked audit audit)
verdict audit "$(holds test "$rc" = 70 -a "$n" = 1)" "process ended with $rc, logged $n"
[ -n "$pid" ] && stop

exit $failed

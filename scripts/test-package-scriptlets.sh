#!/usr/bin/env bash
# test-package-scriptlets.sh — the maintainer scripts must tell an upgrade from a
# removal, and nothing in a build catches them getting it wrong.
#
# Both package formats ship the same two scripts (dist/nora.nfpm.yaml sets
# scripts.preremove / scripts.postinstall at top level) and each spells the argument
# differently: dpkg passes a word, rpm passes the number of instances that remain.
# Ignoring it stopped AND disabled a running registry on every upgrade and never
# started it again — #1035, present for as long as packaging had existed, found only
# by upgrading a live box.
#
# The scripts run here against a stub `systemctl` (plus stubs for the user and
# ownership steps) and the test asserts WHICH verbs were invoked. No systemd, no
# container, no root, so this belongs in the ordinary CI job rather than a polygon
# suite. Point DIST_DIR at another copy of the scripts to check this test still has
# teeth: against the pre-#1035 versions every upgrade case must fail.
set -u

DIST_DIR="${DIST_DIR:-$(cd "$(dirname "$0")/../dist" && pwd)}"
FAILED=0

stub_dir() {
    local d="$1" active="$2"
    mkdir -p "$d/bin"
    cat > "$d/bin/systemctl" <<STUB
#!/bin/sh
echo "systemctl \$*" >> "$d/calls.log"
case "\$*" in
    *is-active*) [ "$active" = yes ] && exit 0 || exit 3 ;;
esac
exit 0
STUB
    for cmd in useradd chown; do
        printf '#!/bin/sh\necho "%s $*" >> "%s/calls.log"\nexit 0\n' "$cmd" "$d" > "$d/bin/$cmd"
    done
    # the nora user is reported missing so the create path is exercised too
    printf '#!/bin/sh\nexit 1\n' > "$d/bin/id"
    chmod +x "$d/bin"/*
    : > "$d/calls.log"
}

# run <name> <script> <active?> <expect-verbs> <forbid-verbs> -- <args...>
run_case() {
    local name="$1" script="$2" active="$3" expect="$4" forbid="$5"; shift 6
    local d; d="$(mktemp -d)"
    stub_dir "$d" "$active"
    local out rc
    out="$(cd "$d" && PATH="$d/bin:$PATH" sh "$DIST_DIR/$script" "$@" 2>&1)"; rc=$?
    local log; log="$(cat "$d/calls.log")"
    local bad=""
    [ "$rc" -eq 0 ] || bad="exit=$rc"
    for verb in $expect; do
        echo "$log" | grep -q -- "$verb" || bad="$bad missing:$verb"
    done
    for verb in $forbid; do
        echo "$log" | grep -q -- "$verb" && bad="$bad unexpected:$verb"
    done
    if [ -n "$bad" ]; then
        printf 'FAIL  %-42s %s\n' "$name" "$bad"
        printf '      calls: %s\n' "$(echo "$log" | tr '\n' '|')"
        printf '      output: %s\n' "$(echo "$out" | tr '\n' '|')"
        FAILED=1
    else
        printf 'ok    %-42s\n' "$name"
    fi
    rm -r "$d"
}

echo "=== maintainer scriptlets (dist: $DIST_DIR) ==="

# prerm: an upgrade must leave a running unit and its enablement alone
run_case "deb prerm upgrade keeps the service"  prerm.sh    yes ""              "stop disable"  -- upgrade 1.3.4
run_case "deb prerm deconfigure keeps it"       prerm.sh    yes ""              "stop disable"  -- deconfigure
run_case "rpm preun upgrade keeps it"           prerm.sh    yes ""              "stop disable"  -- 1
# prerm: a real removal still stops and disables
run_case "deb prerm remove stops+disables"      prerm.sh    yes "stop disable"  ""              -- remove
run_case "rpm preun last removal stops"         prerm.sh    yes "stop disable"  ""              -- 0
run_case "deb prerm remove, already stopped"    prerm.sh    no  "disable"       "stop"          -- remove

# postinst: an upgrade brings the service back; a fresh install does not start it
run_case "deb postinst upgrade restarts"        postinst.sh yes "try-restart"   ""              -- configure 1.3.2
run_case "rpm post upgrade restarts"            postinst.sh yes "try-restart"   ""              -- 2
run_case "deb postinst fresh does not start"    postinst.sh no  "enable"        "try-restart start" -- configure
run_case "rpm post install does not start"      postinst.sh no  "enable"        "try-restart start" -- 1

# a fresh install prints the hint; an upgrade stays quiet
d="$(mktemp -d)"; stub_dir "$d" no
fresh="$(cd "$d" && PATH="$d/bin:$PATH" sh "$DIST_DIR/postinst.sh" configure 2>&1)"
upg="$(cd "$d" && PATH="$d/bin:$PATH" sh "$DIST_DIR/postinst.sh" configure 1.3.2 2>&1)"
if echo "$fresh" | grep -q "Start with" && ! echo "$upg" | grep -q "Start with"; then
    printf 'ok    %-42s\n' "hint on install only"
else
    printf 'FAIL  %-42s fresh=[%s] upgrade=[%s]\n' "hint on install only" "$fresh" "$upg"; FAILED=1
fi
rm -r "$d"

# no systemd on PATH (a container image built from the package) must not fail the install
d="$(mktemp -d)"; stub_dir "$d" no; rm "$d/bin/systemctl"
if (cd "$d" && PATH="$d/bin:/usr/bin:/bin" sh "$DIST_DIR/postinst.sh" configure >/dev/null 2>&1); then
    printf 'ok    %-42s\n' "postinst survives without systemd"
else
    printf 'FAIL  %-42s exit!=0 without systemctl\n' "postinst survives without systemd"; FAILED=1
fi
rm -r "$d"

if [ "$FAILED" -ne 0 ]; then
    echo "=== scriptlet check FAILED ==="
    exit 1
fi
echo "=== scriptlet check passed ==="

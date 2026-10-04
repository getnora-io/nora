#!/usr/bin/env bash
# package-install-check.sh — put the built package on a clean system and assert the
# things only an install can tell us.
#
# Until this existed, `release.yml` built the .deb/.rpm at tag time and nothing ever
# installed one, so a change under dist/ passed every check and was validated by the
# first user to run `apt install` (#1031). Two real defects went out that way: the
# unit file in /lib/systemd/system, forbidden since the /usr merge (#1022, four
# lintian errors, shipped in every release until #1023), and an upgrade that stopped
# the registry and never started it again (#1035).
#
#   package-install-check.sh deb ./nora-amd64.deb [./nora-released.deb]
#   package-install-check.sh rpm ./nora-amd64.rpm [./nora-released.rpm]
#
# The upgrade that #1035 is about is checked by installing the built package over
# itself: both scripts in play are then this build's. The optional third argument
# adds a migration pass from the last released package, which asserts the
# mechanics (rc, unit path, no aliased /lib) rather than the service state — the
# old package's prerm stops the registry and that is not this build's decision.
#
# systemd runs as PID 1 in a privileged container, which on Docker 29 + cgroup v2 is
# what it takes (SYS_ADMIN with a writable cgroup mount was measured not to be enough:
# systemd exits 255 before it logs anything). Privileged means the container shares the
# host's devices, and that is how a container's getty once took over the host's
# /dev/tty1 and tripped the monitoring — so the image masks getty, the getty target,
# the serial/console getty and logind OFFLINE, at build time. A container that cannot
# start a getty cannot take a console away from anybody.
set -u

FORMAT="${1:?usage: package-install-check.sh <deb|rpm> <package> [released-package]}"
PKG="${2:?missing package path}"
OLD_PKG="${3:-}"
PKG=$(readlink -f "$PKG")
[ -n "$OLD_PKG" ] && OLD_PKG=$(readlink -f "$OLD_PKG")

UNIT_PATH=/usr/lib/systemd/system/nora.service
CT="nora-pkgcheck-$FORMAT-$$"
FAILED=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAILED=1; }
check() { # check <description> <expected> <actual>
    if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 — expected [$2], got [$3]"; fi
}
cleanup() { docker rm -f "$CT" >/dev/null 2>&1 || true; }
trap cleanup EXIT

case "$FORMAT" in
    deb)
        BASE=debian:trixie
        INSTALL_SETUP='apt-get update -qq && apt-get install -y -qq --no-install-recommends systemd systemd-sysv curl lintian >/dev/null'
        ;;
    rpm)
        BASE=almalinux:9
        INSTALL_SETUP='dnf install -y -q systemd >/dev/null'  # curl-minimal already provides curl; asking for curl conflicts
        ;;
    *) echo "unknown format: $FORMAT" >&2; exit 2 ;;
esac

echo "=== building the test image ($BASE) ==="
docker build -q -t "nora-pkgcheck-$FORMAT" - >/dev/null <<IMG
FROM $BASE
RUN $INSTALL_SETUP
# See the header: no getty, no logind, so a privileged container cannot grab a console.
RUN systemctl mask getty.target getty@.service console-getty.service serial-getty@.service systemd-logind.service tmp.mount >/dev/null 2>&1 || true
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
IMG

echo "=== booting systemd in a container ==="
docker run -d --name "$CT" --privileged --cgroupns=private \
    -e container=docker --tmpfs /run --tmpfs /run/lock \
    "nora-pkgcheck-$FORMAT" >/dev/null
for _ in $(seq 1 30); do
    state=$(docker exec "$CT" systemctl is-system-running 2>/dev/null || true)
    case "$state" in running | degraded) break ;; esac
    sleep 1
done
check "systemd reached a usable state" "yes" "$(case "$state" in running | degraded) echo yes ;; *) echo "no ($state)" ;; esac)"
[ "$FAILED" -eq 0 ] || { docker logs "$CT" 2>&1 | tail -20; exit 1; }

# Packages are copied to /opt, not /tmp: systemd mounts a tmpfs over /tmp, and
# `docker cp` into a running container writes UNDER such a mount, where the container
# cannot see the file ("cannot access archive"). /opt is plain image filesystem.
inst() { # inst <package-on-host> → install it in the container, echo the rc
    docker cp "$1" "$CT:/opt/$(basename "$1")" >/dev/null
    case "$FORMAT" in
        deb) docker exec "$CT" sh -c "DEBIAN_FRONTEND=noninteractive dpkg --force-confold -i /opt/$(basename "$1") >/opt/inst.log 2>&1; echo \$?" ;;
        rpm) docker exec "$CT" sh -c "rpm -U --force /opt/$(basename "$1") >/opt/inst.log 2>&1; echo \$?" ;;
    esac
}
# `curl -w` prints a code even when it fails, so a trailing `|| echo` would print
# twice ("000000"); take the first line and let an empty answer mean 000.
one() { head -n1; }
health() { docker exec "$CT" sh -c 'curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://127.0.0.1:4000/health 2>/dev/null; echo' | one | sed 's/^$/000/'; }
wait_health() { for _ in $(seq 1 20); do [ "$(health)" = "200" ] && break; sleep 1; done; health; }

echo "=== clean install, shipped defaults untouched ==="
check "package installs" "0" "$(inst "$PKG")"
docker exec "$CT" systemctl start nora >/dev/null 2>&1 || true
# #1025/#1026: the packaged env file must be enough to start. Before that fix the
# service panicked on it and Restart=on-failure looped forever, so `active` here —
# not `activating`, which is systemd's auto-restart wait — is what keeps a package
# that cannot start out of a release.
check "defaults start the service" "active" "$(docker exec "$CT" systemctl is-active nora 2>/dev/null | one)"
check "defaults answer /health" "200" "$(wait_health)"

echo "=== what the package put on the system ==="
check "unit is where systemd looks" "$UNIT_PATH" \
    "$(docker exec "$CT" sh -c "systemctl show -p FragmentPath --value nora.service" 2>/dev/null | one)"
check "unit enabled by the package" "enabled" "$(docker exec "$CT" systemctl is-enabled nora 2>/dev/null | one)"
if [ "$FORMAT" = deb ]; then
    listed=$(docker exec "$CT" sh -c "dpkg -L nora | grep -c '^/lib/systemd' || true" 2>/dev/null | one)
    check "nothing shipped under the aliased /lib path" "0" "$listed"
fi
docker exec "$CT" systemctl restart nora >/dev/null 2>&1 || true
check "restart brings it back" "200" "$(wait_health)"

echo "=== self-upgrade: the same package installed over itself ==="
# This is the hop the maintainer scripts can actually control: BOTH the prerm that
# runs and the postinst that follows come from this build. #1035 lives here — prerm
# must not stop a running registry on an upgrade, and postinst must try-restart it so
# the new binary is picked up. Upgrading FROM an older release cannot be asserted the
# same way: dpkg runs the OLD package's prerm, and up to 1.3.2 that stopped and
# disabled the unit unconditionally, after which `try-restart` deliberately does
# nothing to a stopped unit.
check "self-upgrade returns 0" "0" "$(inst "$PKG")"
check "service still active after the self-upgrade" "active" "$(docker exec "$CT" systemctl is-active nora 2>/dev/null | one)"
check "service still enabled after the self-upgrade" "enabled" "$(docker exec "$CT" systemctl is-enabled nora 2>/dev/null | one)"
check "service answers /health after the self-upgrade" "200" "$(wait_health)"

if [ -n "$OLD_PKG" ]; then
    echo "=== migration from the released package ==="
    # Only the mechanics are asserted here. The released package's own prerm stops
    # the service during the upgrade, so whether it comes back is not this build's
    # decision; what IS this build's decision is that the upgrade succeeds, the unit
    # lands where systemd looks, and nothing is left under the aliased /lib path
    # (#1022). The conffile is edited first so dpkg takes the modified-conffile path,
    # which is where an aborted upgrade could leave the unit stopped and disabled.
    case "$FORMAT" in
        deb) docker exec "$CT" sh -c "dpkg -r nora >/dev/null 2>&1" || true ;;
        rpm) docker exec "$CT" sh -c "rpm -e nora >/dev/null 2>&1" || true ;;
    esac
    check "released package installs" "0" "$(inst "$OLD_PKG")"
    # Written AFTER the old package is in place: rpm takes the env file with it on
    # removal (dpkg keeps a conffile), so writing it earlier left the old release on
    # stock defaults — which up to 1.3.2 could not start at all.
    docker exec "$CT" sh -c "echo NORA_PUBLIC_URL=http://127.0.0.1:4000 >> /etc/nora/nora.env" >/dev/null 2>&1 || true
    docker exec "$CT" systemctl restart nora >/dev/null 2>&1 || true
    check "released version answers /health" "200" "$(wait_health)"
    check "upgrade from the release returns 0" "0" "$(inst "$PKG")"
    check "unit is where systemd looks after the migration" "$UNIT_PATH" \
        "$(docker exec "$CT" sh -c "systemctl show -p FragmentPath --value nora.service" 2>/dev/null | one)"
    # Deliberately not asserted here: whether the service is running or enabled after
    # this hop. The OLD package's scripts decide that and they are already released —
    # on deb its prerm stops the unit, and on rpm its %preun runs AFTER the new %post
    # and disables it, so a 1.3.2 → 1.3.3 upgrade needs one `systemctl enable --now`.
    # From 1.3.3 onward both scripts in play are ours, which is what the self-upgrade
    # pass above asserts.
    printf '  note  after migrating from the released package: active=%s enabled=%s\n' \
        "$(docker exec "$CT" systemctl is-active nora 2>/dev/null | one)" \
        "$(docker exec "$CT" systemctl is-enabled nora 2>/dev/null | one)"
    docker exec "$CT" sh -c "systemctl enable nora >/dev/null 2>&1; systemctl start nora >/dev/null 2>&1" || true
    check "service runs again after enable+start" "200" "$(wait_health)"
fi

echo "=== removal stops and disables ==="
case "$FORMAT" in
    deb) docker exec "$CT" sh -c 'DEBIAN_FRONTEND=noninteractive dpkg -r nora >/dev/null 2>&1' || true ;;
    rpm) docker exec "$CT" sh -c 'rpm -e nora >/dev/null 2>&1' || true ;;
esac
check "service stopped after removal" "inactive" \
    "$(docker exec "$CT" sh -c 'systemctl is-active nora 2>/dev/null; true' | one | sed 's/^$/inactive/')"

if [ "$FORMAT" = deb ]; then
    echo "=== lintian ratchet ==="
    docker cp "$PKG" "$CT:/tmp/ratchet.deb" >/dev/null
    tags=$(docker exec "$CT" sh -c 'lintian -I --no-tag-display-limit /tmp/ratchet.deb 2>/dev/null | sed -E "s/^[A-Z]: [^:]+: //" | awk "{print \$1}" | sort -u' || true)
    baseline="$(cd "$(dirname "$0")/.." && cat dist/lintian-expected.txt 2>/dev/null | grep -v '^#' | grep -v '^$' | sort -u)"
    new_tags=$(comm -23 <(echo "$tags") <(echo "$baseline") | grep -v '^$' || true)
    gone_tags=$(comm -13 <(echo "$tags") <(echo "$baseline") | grep -v '^$' || true)
    if [ -n "$new_tags" ]; then
        fail "new lintian tags (add them to dist/lintian-expected.txt only with a reason): $(echo "$new_tags" | tr '\n' ' ')"
    else
        pass "no lintian tag outside the baseline ($(echo "$tags" | grep -c .) present)"
    fi
    [ -n "$gone_tags" ] && printf '  note  baseline tags no longer reported — ratchet them out of dist/lintian-expected.txt: %s\n' "$(echo "$gone_tags" | tr '\n' ' ')"
fi

echo
if [ "$FAILED" -ne 0 ]; then
    echo "=== $FORMAT package check FAILED ==="
    docker exec "$CT" sh -c 'tail -20 /opt/inst.log 2>/dev/null' || true
    exit 1
fi
echo "=== $FORMAT package check passed ==="

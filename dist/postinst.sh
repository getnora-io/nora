#!/bin/sh
set -e

# Create system user if not exists
if ! id nora >/dev/null 2>&1; then
    useradd --system --shell /usr/sbin/nologin --home-dir /var/lib/nora --no-create-home nora
fi

# Fix ownership (dirs created by nfpm)
chown nora:nora /var/lib/nora /var/log/nora

# Fresh install or upgrade? dpkg passes `configure` with the previous version in $2
# (empty on a first install); rpm passes 1 for an install and 2 for an upgrade. The
# answer decides whether the registry has to be brought back: prerm no longer stops
# it on an upgrade, but the binary underneath the running process has been replaced,
# so the unit still has to be restarted to pick the new one up (#1035).
is_upgrade=no
case "$1" in
    configure)
        [ -n "$2" ] && is_upgrade=yes
        ;;
    2)
        is_upgrade=yes
        ;;
esac

# systemd can be absent — a container image built from the .deb, for instance — in
# which case enabling a unit is meaningless rather than fatal. daemon-reload used to
# run unguarded under `set -e`, so such an install failed outright.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable nora >/dev/null 2>&1 || true
    if [ "$is_upgrade" = yes ]; then
        # try-restart, not restart: a unit the administrator had stopped stays stopped.
        systemctl try-restart nora >/dev/null 2>&1 || true
    fi
fi

if [ "$is_upgrade" = no ]; then
    echo "NORA installed. Start with: systemctl start nora"
    echo "For clients on other hosts, set NORA_PUBLIC_URL in /etc/nora/nora.env first."
fi

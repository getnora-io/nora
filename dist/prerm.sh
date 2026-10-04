#!/bin/sh
set -e

# $1 separates a removal from an upgrade, and the two package formats spell it
# differently: dpkg passes a word (remove, upgrade, deconfigure, failed-upgrade),
# rpm passes the number of instances that will remain (0 on the last removal,
# 1 during an upgrade).
#
# Ignoring it stopped AND disabled a running registry on every upgrade, and nothing
# started it again (#1035): postinst re-enabled the unit but never restarted it, and
# an upgrade that aborted before postinst — a non-interactive dpkg stopping at an
# edited conffile prompt — left the unit both stopped and disabled, so not even a
# reboot brought it back. Under unattended-upgrades the registry went down at night
# and the first signal was clients failing against a dead port.
case "$1" in
    upgrade | deconfigure | failed-upgrade)
        # dpkg: the package is being replaced, not removed.
        exit 0
        ;;
    [1-9]*)
        # rpm: an instance remains after this operation, so this is an upgrade.
        exit 0
        ;;
esac

# A genuine removal: stop the service and drop its enablement.
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet nora 2>/dev/null; then
        systemctl stop nora
    fi
    systemctl disable nora >/dev/null 2>&1 || true
fi

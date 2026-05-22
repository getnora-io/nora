#!/bin/sh
set -e

# Stop and disable service before removal
if systemctl is-active --quiet nora 2>/dev/null; then
    systemctl stop nora
fi
systemctl disable nora >/dev/null 2>&1 || true

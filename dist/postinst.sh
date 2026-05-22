#!/bin/sh
set -e

# Create system user if not exists
if ! id nora >/dev/null 2>&1; then
    useradd --system --shell /usr/sbin/nologin --home-dir /var/lib/nora --no-create-home nora
fi

# Fix ownership (dirs created by nfpm)
chown nora:nora /var/lib/nora /var/log/nora

# Reload systemd and enable service
systemctl daemon-reload
systemctl enable nora >/dev/null 2>&1 || true

echo "NORA installed. Start with: systemctl start nora"

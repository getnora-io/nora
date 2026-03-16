#!/usr/bin/env bash
set -euo pipefail

# NORA Artifact Registry — install script
# Usage: curl -fsSL https://getnora.io/install.sh | bash

VERSION="${NORA_VERSION:-latest}"
ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/nora"
DATA_DIR="/var/lib/nora"
LOG_DIR="/var/log/nora"

case "$ARCH" in
    x86_64|amd64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

echo "Installing NORA ($OS/$ARCH)..."

# Download binary
if [ "$VERSION" = "latest" ]; then
    DOWNLOAD_URL="https://github.com/getnora-io/nora/releases/latest/download/nora-${OS}-${ARCH}"
else
    DOWNLOAD_URL="https://github.com/getnora-io/nora/releases/download/${VERSION}/nora-${OS}-${ARCH}"
fi

echo "Downloading from $DOWNLOAD_URL..."
if command -v curl &>/dev/null; then
    curl -fsSL -o /tmp/nora "$DOWNLOAD_URL"
elif command -v wget &>/dev/null; then
    wget -qO /tmp/nora "$DOWNLOAD_URL"
else
    echo "Error: curl or wget required"; exit 1
fi

chmod +x /tmp/nora
sudo mv /tmp/nora "$INSTALL_DIR/nora"

# Create system user
if ! id nora &>/dev/null; then
    sudo useradd --system --shell /usr/sbin/nologin --home-dir "$DATA_DIR" --create-home nora
    echo "Created system user: nora"
fi

# Create directories
sudo mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
sudo chown nora:nora "$DATA_DIR" "$LOG_DIR"

# Install default config if not exists
if [ ! -f "$CONFIG_DIR/nora.env" ]; then
    cat > /tmp/nora.env << 'ENVEOF'
NORA_HOST=0.0.0.0
NORA_PORT=4000
NORA_STORAGE_PATH=/var/lib/nora
ENVEOF
    sudo mv /tmp/nora.env "$CONFIG_DIR/nora.env"
    sudo chmod 600 "$CONFIG_DIR/nora.env"
    sudo chown nora:nora "$CONFIG_DIR/nora.env"
    echo "Created default config: $CONFIG_DIR/nora.env"
fi

# Install systemd service
if [ -d /etc/systemd/system ]; then
    cat > /tmp/nora.service << 'SVCEOF'
[Unit]
Description=NORA Artifact Registry
Documentation=https://getnora.dev
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nora
Group=nora
ExecStart=/usr/local/bin/nora serve
WorkingDirectory=/etc/nora
Restart=on-failure
RestartSec=5
LimitNOFILE=65535
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/nora /var/log/nora
PrivateTmp=true
EnvironmentFile=-/etc/nora/nora.env

[Install]
WantedBy=multi-user.target
SVCEOF
    sudo mv /tmp/nora.service /etc/systemd/system/nora.service
    sudo systemctl daemon-reload
    sudo systemctl enable nora
    echo "Installed systemd service: nora"
fi

echo ""
echo "NORA installed successfully!"
echo ""
echo "  Binary:  $INSTALL_DIR/nora"
echo "  Config:  $CONFIG_DIR/nora.env"
echo "  Data:    $DATA_DIR"
echo "  Version: $(nora --version 2>/dev/null || echo 'unknown')"
echo ""
echo "Next steps:"
echo "  1. Edit $CONFIG_DIR/nora.env"
echo "  2. sudo systemctl start nora"
echo "  3. curl http://localhost:4000/health"
echo ""

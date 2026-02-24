#!/usr/bin/env sh
# NORA installer — https://getnora.io/install.sh
# Usage: curl -fsSL https://getnora.io/install.sh | sh

set -e

REPO="getnora-io/nora"
BINARY="nora"
INSTALL_DIR="/usr/local/bin"

# ── Detect OS and architecture ──────────────────────────────────────────────

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)  os="linux" ;;
  Darwin) os="darwin" ;;
  *)
    echo "Unsupported OS: $OS"
    echo "Please download manually: https://github.com/$REPO/releases/latest"
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64 | amd64) arch="amd64" ;;
  aarch64 | arm64) arch="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH"
    echo "Please download manually: https://github.com/$REPO/releases/latest"
    exit 1
    ;;
esac

ASSET="${BINARY}-${os}-${arch}"

# ── Get latest release version ──────────────────────────────────────────────

VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
  | grep '"tag_name"' \
  | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"

if [ -z "$VERSION" ]; then
  echo "Failed to get latest version"
  exit 1
fi

echo "Installing NORA $VERSION ($os/$arch)..."

# ── Download binary and checksum ────────────────────────────────────────────

BASE_URL="https://github.com/$REPO/releases/download/$VERSION"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Downloading $ASSET..."
curl -fsSL "$BASE_URL/$ASSET" -o "$TMP_DIR/$BINARY"
curl -fsSL "$BASE_URL/$ASSET.sha256" -o "$TMP_DIR/$ASSET.sha256"

# ── Verify checksum ─────────────────────────────────────────────────────────

echo "Verifying checksum..."
EXPECTED="$(awk '{print $1}' "$TMP_DIR/$ASSET.sha256")"
ACTUAL="$(sha256sum "$TMP_DIR/$BINARY" | awk '{print $1}')"

if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "Checksum mismatch!"
  echo "  Expected: $EXPECTED"
  echo "  Actual:   $ACTUAL"
  exit 1
fi

echo "Checksum OK"

# ── Install ─────────────────────────────────────────────────────────────────

chmod +x "$TMP_DIR/$BINARY"

if [ -w "$INSTALL_DIR" ]; then
  mv "$TMP_DIR/$BINARY" "$INSTALL_DIR/$BINARY"
elif command -v sudo >/dev/null 2>&1; then
  sudo mv "$TMP_DIR/$BINARY" "$INSTALL_DIR/$BINARY"
else
  # Fallback to ~/.local/bin
  INSTALL_DIR="$HOME/.local/bin"
  mkdir -p "$INSTALL_DIR"
  mv "$TMP_DIR/$BINARY" "$INSTALL_DIR/$BINARY"
  echo "Installed to $INSTALL_DIR/$BINARY"
  echo "Make sure $INSTALL_DIR is in your PATH"
fi

# ── Done ────────────────────────────────────────────────────────────────────

echo ""
echo "NORA $VERSION installed to $INSTALL_DIR/$BINARY"
echo ""
nora --version 2>/dev/null || true

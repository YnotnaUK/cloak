#!/usr/bin/env bash
set -e

REPO="ynotnauk/cloak"
INSTALL_DIR="/usr/local/bin"

# 1. Detect OS
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
  linux*)  OS="linux" ;;
  darwin*) OS="darwin" ;;
  *)       echo "Unsupported OS: $OS"; exit 1 ;;
esac

# 2. Detect Architecture
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)       echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# 3. Get Latest Release Tag
echo "Fetching latest release information..."
LATEST_TAG=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST_TAG" ]; then
  echo "Error: Could not retrieve latest release."
  exit 1
fi

BINARY_NAME="cloak-${OS}-${ARCH}"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/${BINARY_NAME}"

# 4. Download Binary
TMP_FILE=$(mktemp)
echo "Downloading cloak ${LATEST_TAG} for ${OS}/${ARCH}..."
curl -sL "$DOWNLOAD_URL" -o "$TMP_FILE"
chmod +x "$TMP_FILE"

# 5. Install Binary
if [ -w "$INSTALL_DIR" ]; then
  mv "$TMP_FILE" "${INSTALL_DIR}/cloak"
else
  echo "Escalating privileges to install into ${INSTALL_DIR}..."
  sudo mv "$TMP_FILE" "${INSTALL_DIR}/cloak"
fi

echo "Successfully installed cloak to ${INSTALL_DIR}/cloak"
cloak version

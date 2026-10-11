#!/usr/bin/env bash
set -euo pipefail

REPO="ynotnauk/cloak"
INSTALL_DIR="/usr/local/bin"
PREVIEW_SERIES=""

if [[ $# -gt 0 ]]; then
  if [[ $# -ne 2 || "$1" != --preview || ! "$2" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    echo "Usage: bash install.sh [--preview <major.minor>]" >&2
    exit 1
  fi
  PREVIEW_SERIES="$2"
  if ! command -v jq >/dev/null 2>&1; then
    echo "Error: Preview installation requires jq to select a release." >&2
    exit 1
  fi
fi

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
if [[ -z "$PREVIEW_SERIES" ]]; then
  LATEST_URL=$(curl -fsSL -o /dev/null -w '%{url_effective}' \
    "https://github.com/${REPO}/releases/latest")
  LATEST_TAG="${LATEST_URL##*/}"
  CANONICAL_URL=$(printf '%s' "$LATEST_URL" | tr '[:upper:]' '[:lower:]')
  if [[ "$CANONICAL_URL" != "https://github.com/${REPO}/releases/tag/"* ]]; then
    echo "Error: Could not resolve the latest stable release." >&2
    exit 1
  fi
else
  PAGE=1
  LATEST_RELEASE=null
  while :; do
    RELEASES=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases?per_page=100&page=${PAGE}")
    if [[ "$(printf '%s' "$RELEASES" | jq -er 'if type == "array" then length else error("Expected a releases array") end')" == 0 ]]; then
      break
    fi
    LATEST_RELEASE=$(printf '%s' "$RELEASES" | jq -c \
      --arg series "$PREVIEW_SERIES" --argjson latest "$LATEST_RELEASE" '
        [
          .[] | select(.draft == false and .prerelease == true)
          | select(.tag_name | startswith("v" + $series + "."))
          | select(.tag_name | test("^v[0-9]+\\.[0-9]+\\.(0|[1-9][0-9]*)-preview\\.[0-9]{14}$"))
        ] + (if $latest == null then [] else [$latest] end)
        | sort_by(
            .tag_name
            | capture("^v[0-9]+\\.[0-9]+\\.(?<patch>[0-9]+)-preview\\.(?<timestamp>[0-9]{14})$")
            | [(.patch | length), .patch, .timestamp]
          ) | last
      ')
    PAGE=$((PAGE + 1))
  done
  if [[ "$LATEST_RELEASE" == null ]]; then
    echo "Error: No preview release found for ${PREVIEW_SERIES}." >&2
    exit 1
  fi
  LATEST_TAG=$(printf '%s' "$LATEST_RELEASE" | jq -er '.tag_name')
fi

if [[ ! "$LATEST_TAG" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "Error: Invalid release tag." >&2
  exit 1
fi

BINARY_NAME="cloak-${OS}-${ARCH}"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/${BINARY_NAME}"

# 4. Download Binary
TMP_FILE=$(mktemp)
trap 'rm -f -- "$TMP_FILE"' EXIT
echo "Downloading cloak ${LATEST_TAG} for ${OS}/${ARCH}..."
curl -fsSL "$DOWNLOAD_URL" -o "$TMP_FILE"
if [[ ! -s "$TMP_FILE" ]]; then
  echo "Error: Downloaded release binary is empty." >&2
  exit 1
fi
chmod +x "$TMP_FILE"

# 5. Install Binary
if [ -w "$INSTALL_DIR" ]; then
  mv "$TMP_FILE" "${INSTALL_DIR}/cloak"
else
  echo "Escalating privileges to install into ${INSTALL_DIR}..."
  sudo mv "$TMP_FILE" "${INSTALL_DIR}/cloak"
fi

echo "Successfully installed cloak to ${INSTALL_DIR}/cloak"
"${INSTALL_DIR}/cloak" version

#!/usr/bin/env sh
set -eu

REPO="timuric/bottledeck"
BIN_NAME="bottledeck"
INSTALL_DIR="${BOTTLEDECK_INSTALL_DIR:-$HOME/.local/bin}"

say() {
  printf '%s\n' "$*"
}

err() {
  printf 'bottledeck installer error: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    err "required command '$1' was not found in PATH"
  fi
}

need_cmd curl
need_cmd tar
need_cmd uname

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin)
    case "$ARCH" in
      arm64|aarch64) TARGET="aarch64-apple-darwin" ;;
      x86_64)        TARGET="x86_64-apple-darwin" ;;
      *)             err "unsupported macOS architecture: $ARCH" ;;
    esac
    ;;
  Linux)
    case "$ARCH" in
      x86_64|amd64)  TARGET="x86_64-unknown-linux-gnu" ;;
      aarch64|arm64) TARGET="aarch64-unknown-linux-gnu" ;;
      *)             err "unsupported Linux architecture: $ARCH" ;;
    esac
    ;;
  *)
    err "unsupported OS: $OS (install from source via: cargo install --git https://github.com/$REPO)"
    ;;
esac

if [ -n "${BOTTLEDECK_VERSION:-}" ]; then
  case "$BOTTLEDECK_VERSION" in
    v*) TAG="$BOTTLEDECK_VERSION" ;;
    *)  TAG="v$BOTTLEDECK_VERSION" ;;
  esac
else
  # Follow the releases/latest redirect first: it isn't subject to the API's 60/hour limit.
  TAG="$(
    curl -fsSL -o /dev/null -w '%{url_effective}' \
      -H "User-Agent: bottledeck-installer" \
      "https://github.com/$REPO/releases/latest" 2>/dev/null \
    | sed -n 's#.*/releases/tag/\([^/?#]*\).*#\1#p'
  )"
  if [ -z "$TAG" ]; then
    TAG="$(
      curl -fsSL \
        -H "Accept: application/vnd.github+json" \
        -H "User-Agent: bottledeck-installer" \
        "https://api.github.com/repos/$REPO/releases/latest" \
      | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
      | head -n 1
    )"
  fi
  [ -n "$TAG" ] || err "could not determine latest release tag from GitHub"
fi

ARCHIVE="${BIN_NAME}-${TAG}-${TARGET}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"
ARCHIVE_URL="${BASE_URL}/${ARCHIVE}"
SUMS_URL="${BASE_URL}/SHA256SUMS.txt"

TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t bottledeck)"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

say "Installing ${BIN_NAME} ${TAG} (${TARGET})..."
curl -fsSL "$ARCHIVE_URL" -o "${TMP_DIR}/${ARCHIVE}" || err "failed to download ${ARCHIVE_URL}"
curl -fsSL "$SUMS_URL" -o "${TMP_DIR}/SHA256SUMS.txt" || err "failed to download ${SUMS_URL}"

EXPECTED_SHA="$(awk -v f="$ARCHIVE" '{ gsub(/^\*/, "", $2); if ($2 == f) { print tolower($1); exit } }' "${TMP_DIR}/SHA256SUMS.txt")"
[ -n "$EXPECTED_SHA" ] || err "checksum for ${ARCHIVE} not found in SHA256SUMS.txt"

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_SHA="$(sha256sum "${TMP_DIR}/${ARCHIVE}" | awk '{ print tolower($1) }')"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL_SHA="$(shasum -a 256 "${TMP_DIR}/${ARCHIVE}" | awk '{ print tolower($1) }')"
else
  err "neither sha256sum nor shasum found to verify archive integrity"
fi

if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
  err "SHA256 mismatch for ${ARCHIVE} (expected ${EXPECTED_SHA}, got ${ACTUAL_SHA})"
fi

tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "$TMP_DIR"
[ -f "${TMP_DIR}/${BIN_NAME}" ] || err "archive did not contain ${BIN_NAME} binary"

mkdir -p "$INSTALL_DIR"
STAGE="${INSTALL_DIR}/.${BIN_NAME}.new.$$"
cp "${TMP_DIR}/${BIN_NAME}" "$STAGE"
chmod 755 "$STAGE"
mv "$STAGE" "${INSTALL_DIR}/${BIN_NAME}"

say ""
say "  ◆ bottledeck ${TAG} installed to ${INSTALL_DIR}/${BIN_NAME}"
say ""

case ":${PATH}:" in
  *":${INSTALL_DIR}:"*)
    say "Run \`bottledeck\` to open the interactive TUI, or \`bottledeck update\` anytime to upgrade."
    ;;
  *)
    say "Add ${INSTALL_DIR} to your PATH:"
    say "  export PATH=\"${INSTALL_DIR}:\$PATH\""
    say ""
    say "Then run \`bottledeck\` to open the interactive TUI."
    ;;
esac

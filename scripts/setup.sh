#!/usr/bin/env bash
# Download the architecture-specific standalone analysis binaries that chennai's
# non-atom backends rely on, and install them onto a directory on PATH.
#
#   rusi  + golem   <- cdxgen-plugins-bin release (Rust + Go data-flow slicing)
#   dosai (full)    <- owasp-dep-scan/dosai release (.NET data-flow slicing)
#   blint           <- pip/uv package (binary / APK / IPA analysis); needs LLVM
#
# Binaries are installed to $HOME/.local/bin by default, or /usr/local/bin with
# --system (used by the container image). chennai resolves each tool from PATH
# (or the RUSI_CMD / GOLEM_CMD / DOSAI_CMD / BLINT_CMD overrides), so once they
# are installed here no environment variables are required.
#
# Usage:
#   scripts/setup.sh [--system] [--prefix DIR] [--force] [--no-blint]
set -euo pipefail

# Default to each project's latest release; set a tag (e.g. v2.5.1) to pin.
CDXGEN_PLUGINS_BIN_VERSION="${CDXGEN_PLUGINS_BIN_VERSION:-latest}"
DOSAI_VERSION="${DOSAI_VERSION:-latest}"

# Build a release "download" base URL that supports both `latest` and pinned tags.
release_base() { # owner/repo version
  if [ "$2" = "latest" ] || [ -z "$2" ]; then
    echo "https://github.com/$1/releases/latest/download"
  else
    echo "https://github.com/$1/releases/download/$2"
  fi
}
PLUGINS_BASE="$(release_base "cdxgen/cdxgen-plugins-bin" "${CDXGEN_PLUGINS_BIN_VERSION}")"
DOSAI_BASE="$(release_base "owasp-dep-scan/dosai" "${DOSAI_VERSION}")"

PREFIX=""
SYSTEM=0
FORCE=0
INSTALL_BLINT=1

while [ $# -gt 0 ]; do
  case "$1" in
    --system) SYSTEM=1 ;;
    --prefix) PREFIX="$2"; shift ;;
    --prefix=*) PREFIX="${1#*=}" ;;
    --force) FORCE=1 ;;
    --no-blint) INSTALL_BLINT=0 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

# --- Resolve install directory ------------------------------------------------
if [ -z "$PREFIX" ]; then
  if [ "$SYSTEM" -eq 1 ]; then
    PREFIX="/usr/local/bin"
  else
    PREFIX="${HOME}/.local/bin"
  fi
fi
mkdir -p "$PREFIX"
if [ ! -w "$PREFIX" ]; then
  echo "error: install dir '$PREFIX' is not writable. Re-run with sudo or --prefix." >&2
  exit 1
fi

# --- Detect OS / architecture -------------------------------------------------
uname_s="$(uname -s)"
uname_m="$(uname -m)"
case "$uname_s" in
  Linux)  PB_OS="linux";  DOSAI_OS="linux" ;;
  Darwin) PB_OS="darwin"; DOSAI_OS="osx" ;;
  *) echo "error: unsupported OS '$uname_s' (use the container image on Windows)." >&2; exit 1 ;;
esac
case "$uname_m" in
  x86_64|amd64)  PB_ARCH="amd64"; DOSAI_ARCH="$([ "$DOSAI_OS" = osx ] && echo x64 || echo amd64)" ;;
  aarch64|arm64) PB_ARCH="arm64"; DOSAI_ARCH="arm64" ;;
  *) echo "error: unsupported architecture '$uname_m'." >&2; exit 1 ;;
esac

fetch() { # url dest
  echo "  -> $(basename "$2")"
  if command -v curl >/dev/null 2>&1; then
    curl -fSL --retry 3 -o "$2" "$1"
  else
    wget -q -O "$2" "$1"
  fi
}

install_bin() { # url dest_name
  local url="$1" name="$2" dest="${PREFIX}/$2"
  if [ "$FORCE" -eq 0 ] && command -v "$name" >/dev/null 2>&1; then
    echo "  $name already on PATH ($(command -v "$name")); skipping (use --force to override)"
    return
  fi
  fetch "$url" "$dest"
  chmod +x "$dest"
  # Clear macOS Gatekeeper quarantine on downloaded binaries.
  if [ "$PB_OS" = "darwin" ]; then xattr -d com.apple.quarantine "$dest" 2>/dev/null || true; fi
}

echo "==> Installing standalone analysis binaries into ${PREFIX}"
echo "    cdxgen-plugins-bin ${CDXGEN_PLUGINS_BIN_VERSION}, dosai ${DOSAI_VERSION} (${PB_OS}/${PB_ARCH})"

install_bin "${PLUGINS_BASE}/rusi-${PB_OS}-${PB_ARCH}"  "rusi"
install_bin "${PLUGINS_BASE}/golem-${PB_OS}-${PB_ARCH}" "golem"
install_bin "${DOSAI_BASE}/Dosai-${DOSAI_OS}-${DOSAI_ARCH}-full" "dosai"

# ripgrep: powers chennai's `ripgrep` source-search tool (all modes).
install_ripgrep() {
  if [ "$FORCE" -eq 0 ] && command -v rg >/dev/null 2>&1; then
    echo "  rg already on PATH ($(command -v rg)); skipping"
    return
  fi
  local ver="${RIPGREP_VERSION:-14.1.1}" triple
  case "${PB_OS}-${PB_ARCH}" in
    linux-amd64)  triple="x86_64-unknown-linux-musl" ;;
    linux-arm64)  triple="aarch64-unknown-linux-gnu" ;;
    darwin-amd64) triple="x86_64-apple-darwin" ;;
    darwin-arm64) triple="aarch64-apple-darwin" ;;
  esac
  local url="https://github.com/BurntSushi/ripgrep/releases/download/${ver}/ripgrep-${ver}-${triple}.tar.gz"
  local tmp; tmp="$(mktemp -d)"
  echo "  -> rg (ripgrep ${ver})"
  fetch "$url" "${tmp}/rg.tar.gz"
  tar -xzf "${tmp}/rg.tar.gz" -C "$tmp"
  cp "${tmp}"/ripgrep-*/rg "${PREFIX}/rg"
  chmod +x "${PREFIX}/rg"
  [ "$PB_OS" = "darwin" ] && xattr -d com.apple.quarantine "${PREFIX}/rg" 2>/dev/null || true
  rm -rf "$tmp"
}
install_ripgrep

# --- Verify -------------------------------------------------------------------
for tool in rusi golem dosai; do
  if "${PREFIX}/${tool}" --version >/dev/null 2>&1; then
    echo "  ok: $("${PREFIX}/${tool}" --version 2>&1 | head -n1)"
  else
    echo "  warning: '${tool}' did not respond to --version; verify manually" >&2
  fi
done

# --- blint (Python package, needs LLVM for disassembly) -----------------------
if [ "$INSTALL_BLINT" -eq 1 ]; then
  echo "==> Installing blint (binary / APK / IPA analysis)"
  if command -v blint >/dev/null 2>&1 && [ "$FORCE" -eq 0 ]; then
    echo "  blint already on PATH ($(command -v blint)); skipping"
  elif command -v uv >/dev/null 2>&1; then
    uv tool install --force "blint[extended]" || uv tool install --force blint
  elif command -v pipx >/dev/null 2>&1; then
    pipx install --force "blint[extended]" || pipx install --force blint
  elif command -v pip3 >/dev/null 2>&1; then
    pip3 install --user --upgrade "blint[extended]" || pip3 install --user --upgrade blint
  else
    echo "  warning: no uv/pipx/pip found; install blint manually: pip install 'blint[extended]'" >&2
  fi
  echo "  note: blint disassembly needs LLVM (set NYXSTONE_LLVM_PREFIX);"
  echo "        APK/IPA depth needs the Android SDK. The container image bundles both."
fi

# --- PATH hint ----------------------------------------------------------------
case ":${PATH}:" in
  *":${PREFIX}:"*) ;;
  *) echo ""
     echo "NOTE: ${PREFIX} is not on your PATH. Add this to your shell profile:"
     echo "      export PATH=\"${PREFIX}:\$PATH\"" ;;
esac

echo "==> Done."

#!/usr/bin/env bash
# Build chennai and assemble npm packages for local testing.
# Usage: bash scripts/build-local.sh
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
wrapper="$root/wrapper/nodejs"

echo "==> Building engine (sbt stage)"
(cd "$root/engine" && sbt -batch stage)

echo "==> Building engine native image (GraalVM)"
(cd "$root/engine" && bash "$root/ci/native-image.sh" 2>/dev/null) && ENGINE_NATIVE=true || {
  echo "Native image build skipped (GraalVM not available), using JAR stage distribution"
  ENGINE_NATIVE=false
}

echo "==> Building TUI (cargo build --release)"
(cd "$root/tui" && cargo build --release)

echo "==> Assembling npm packages..."
cd "$wrapper"

# Ensure the parent package has license and readme
node scripts/assemble.mjs

# Stage the JAR distribution for the jar fallback
if [ -d "$root/engine/target/universal/stage" ]; then
  node scripts/assemble.mjs @appthreat/chennai-jar \
    tui/target/release/chennai \
    engine/target/universal/stage
fi

# Native engine binary
ENGINE_BINARY="$root/engine/target/graalvm-native-image/chennai-engine"
TUI_BINARY="$root/tui/target/release/chennai"

LOCAL_PLATFORM=""
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)   LOCAL_PLATFORM="linux-amd64" ;;
  Linux/aarch64)  LOCAL_PLATFORM="linux-arm64" ;;
  Darwin/arm64)   LOCAL_PLATFORM="darwin-arm64" ;;
  Darwin/x86_64)  LOCAL_PLATFORM="darwin-amd64" ;;
esac

if [ -n "$LOCAL_PLATFORM" ] && [ -f "$ENGINE_BINARY" ]; then
  node scripts/assemble.mjs "@appthreat/chennai-$LOCAL_PLATFORM" "$TUI_BINARY" "$ENGINE_BINARY"
fi

echo ""
echo "=== Local packages assembled ==="
ls -la packages/*/bin/ 2>/dev/null || true

echo ""
echo "To test locally:"
echo "  cd $wrapper"
echo "  npm pack --workspace packages/chennai"
echo "  npm install -g ./appthreat-chennai-*.tgz"
echo "  chennai --help"

#!/usr/bin/env bash
# Build the chennai engine (Scala GraalVM native-image) and TUI (Rust).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
engine_native="${ENGINE_NATIVE:-true}"

echo "==> Building engine (sbt stage)"
(cd "$root/engine" && sbt -batch stage)

if [[ "$engine_native" == "true" ]]; then
  echo "==> Building engine native image (GraalVM)"
  (cd "$root/engine" && bash "$root/ci/native-image.sh")
fi

echo "==> Building TUI (cargo build --release)"
(cd "$root/tui" && cargo build --release)

echo
echo "Done. Binaries:"
echo "  TUI:    $root/tui/target/release/chennai"
if [[ "$engine_native" == "true" ]]; then
  echo "  Engine: $root/engine/target/graalvm-native-image/chennai-engine"
fi
echo "  Engine: $root/engine/target/universal/stage/bin/chennai-engine (script)"

#!/usr/bin/env bash
# Build the chennai engine (Scala) and TUI (Rust).
# Supported targets: linux, macos.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Building engine (sbt stage)"
(cd "$root/engine" && sbt -batch scalafmt stage)

echo "==> Building TUI (cargo build --release)"
(cd "$root/tui" && cargo build --release)

echo
echo "Done. Run:"
echo "  $root/tui/target/release/chennai <source-or-reports-dir>"
echo "(the TUI auto-detects engine/target/universal/stage/bin/chennai-engine)"

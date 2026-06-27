#!/usr/bin/env bash
set -euo pipefail

echo "Building chennai engine native image with GraalVM..."
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}/../engine"
sbt "GraalVMNativeImage / packageBin"

if [ -f "target/graalvm-native-image/chennai-engine" ]; then
    chmod +x target/graalvm-native-image/chennai-engine
    echo "chennai engine native image built successfully."
else
    echo "chennai engine native image was not built correctly."
    exit 1
fi

#!/usr/bin/env bash
set -euo pipefail

echo "Building chennai engine native image with GraalVM..."
sbt "GraalVMNativeImage / packageBin"

if [ -f "target/graalvm-native-image/chennai-engine" ]; then
    chmod +x target/graalvm-native-image/chennai-engine
    echo "chennai engine native image built successfully."
else
    echo "chennai engine native image was not built correctly."
    exit 1
fi

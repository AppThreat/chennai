#!/usr/bin/env bash
# Trace the chennai-engine executable using GraalVM native-image-agent to collect
# reachability metadata.  Run this every time dependencies change.
#
# Usage:
#   bash ci/trace-native-image.sh [project-dir ...]
#
# Each project-dir is searched for .atom files (max depth 2).  The engine opens
# each atom and runs a battery of queries to exercise code paths.
#
# Prerequisites:
#   - GraalVM CE 25+ with native-image (sdk use java 25.0.2-graalce)

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
CONFIG_DIR="${REPO_ROOT}/engine/src/main/resources/META-INF/native-image"

cd "${REPO_ROOT}/engine"

echo "=== Building engine stage ==="
sbt clean stage

ENGINE_SCRIPT="${REPO_ROOT}/engine/target/universal/stage/bin/chennai-engine"
if [ ! -f "$ENGINE_SCRIPT" ]; then
  echo "Engine stage script not found at ${ENGINE_SCRIPT}" >&2
  exit 1
fi

AGENT_FLAG="-agentlib:native-image-agent=config-merge-dir=${CONFIG_DIR}"

# Bare --serve ping/close cycle to capture initialisation paths.
echo ""
echo "=== Pass 1: bare --serve ==="
printf '{"id":1,"cmd":"ping","args":{}}\n{"id":2,"cmd":"close","args":{}}\n' | \
  "${ENGINE_SCRIPT}" -J-XX:+UseParallelGC -J-XX:MinRAMPercentage=30 -J-XX:MaxRAMPercentage=90 \
    "-J${AGENT_FLAG}" --serve || true

# Collect .atom files from the given project directories (depth ≤ 2).
ATOM_FILES=()
for DIR in "$@"; do
  while IFS= read -r -d '' f; do
    ATOM_FILES+=("$f")
  done < <(find "$DIR" -maxdepth 2 -name '*.atom' -type f -print0 2>/dev/null || true)
done

if [ ${#ATOM_FILES[@]} -eq 0 ]; then
  echo "No .atom files found in arguments; skipping query passes."
else
  for ATOM in "${ATOM_FILES[@]}"; do
    echo ""
    echo "=== Tracing with atom: ${ATOM} ==="

    BASE_OPTS=(
      -J-XX:+UseParallelGC
      -J-XX:MinRAMPercentage=30
      -J-XX:MaxRAMPercentage=90
      "-J${AGENT_FLAG}"
      --serve
      --atom "$ATOM"
    )

    # Send a sequence of NDJSON requests via stdin.  Brief sleeps between
    # each to let the engine finish processing before the next line arrives.
    {
      echo '{"id":1,"cmd":"open","args":{"path":"'"$ATOM"'"}}'
      sleep 1

      echo '{"id":2,"cmd":"summary","args":{}}'
      sleep 1

      for KIND in finding dependency license; do
        echo '{"id":3,"cmd":"query","args":{"kind":"'"$KIND"'","limit":5}}'
        sleep 0.5
      done

      echo '{"id":4,"cmd":"flows","args":{"expr":"dataflows","source":""}}'
      sleep 1

      echo '{"id":5,"cmd":"eval","args":{"expr":"atom.cpg.all.toJson"}}'
      sleep 0.5

      echo '{"id":6,"cmd":"eval","args":{"expr":"atom.cpg.finding.limit(5).toJson"}}'
      sleep 0.5

      echo '{"id":7,"cmd":"detail","args":{"kind":"finding","key":""}}'
      sleep 0.5

      echo '{"id":8,"cmd":"enrich","args":{"bom":"/nonexistent/bom.json"}}'
      sleep 0.5

      echo '{"id":9,"cmd":"algo","args":{}}'
      sleep 0.5

      echo '{"id":10,"cmd":"close","args":{}}'
      sleep 0.5
    } | "${ENGINE_SCRIPT}" "${BASE_OPTS[@]}" >/dev/null 2>&1 || true

    echo "Done tracing ${ATOM}"
  done
fi

echo ""
echo "=== Regenerated config in ${CONFIG_DIR} ==="
ls -la "${CONFIG_DIR}/"

echo ""
echo "Now rebuild with: (cd engine && sbt GraalVMNativeImage / packageBin)"

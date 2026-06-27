#!/usr/bin/env bash
# Build Linux musl native images in a musl-capable GraalVM container.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

IMAGE="${CHENNAI_GRAALVM_MUSL_IMAGE:-ghcr.io/graalvm/native-image-community:25-muslib}"
ENGINE="${CHENNAI_CONTAINER_ENGINE:-}"
ARCH=""
OUTPUT=""

usage() {
  cat <<'EOF'
Usage: bash ci/native-image-musl.sh --arch <amd64|arm64> --output <path>

Options:
  --arch <arch>         Target architecture (amd64 or arm64).
  --output <path>       Output binary path.
  --image <image>       Override build container image.
  --engine <binary>     Override container engine binary.
  -h, --help            Show help.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --arch) ARCH="${2:-}"; shift 2 ;;
    --output) OUTPUT="${2:-}"; shift 2 ;;
    --image) IMAGE="${2:-}"; shift 2 ;;
    --engine) ENGINE="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "${ARCH}" || -z "${OUTPUT}" ]]; then
  echo "Both --arch and --output are required." >&2
  usage; exit 1
fi

if [[ -z "${ENGINE}" ]]; then
  if command -v docker >/dev/null 2>&1; then
    ENGINE="$(command -v docker)"
  elif command -v nerdctl >/dev/null 2>&1; then
    ENGINE="$(command -v nerdctl)"
  elif command -v podman >/dev/null 2>&1; then
    ENGINE="$(command -v podman)"
  else
    echo "No container engine found." >&2
    exit 1
  fi
fi

if [[ -z "${GITHUB_TOKEN:-}" && -n "${GH_TOKEN:-}" ]]; then
  export GITHUB_TOKEN="${GH_TOKEN}"
fi
if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  export GITHUB_TOKEN="dummy"
fi

mkdir -p "${REPO_ROOT}/target/graalvm-native-image"
mkdir -p "${REPO_ROOT}/.cache/native-image-musl"

SBT_CACHE="${REPO_ROOT}/.cache/native-image-musl/sbt"
IVY_CACHE="${REPO_ROOT}/.cache/native-image-musl/ivy2"
COURSIER_CACHE="${REPO_ROOT}/.cache/native-image-musl/coursier"
mkdir -p "${SBT_CACHE}" "${IVY_CACHE}" "${COURSIER_CACHE}"

OUTPUT_ABS="${REPO_ROOT}/${OUTPUT}"

echo "Building linux/${ARCH} musl native image..."

"${ENGINE}" run --rm \
  --platform "linux/${ARCH}" \
  --entrypoint /bin/bash \
  -e HOME=/tmp/home \
  -e GITHUB_TOKEN="${GITHUB_TOKEN}" \
  -e CHENNAI_GRAALVM_LIBC=musl \
  -e COURSIER_CACHE=/tmp/home/.cache/coursier \
  -v "${REPO_ROOT}:/workspace" \
  -v "${SBT_CACHE}:/tmp/home/.sbt" \
  -v "${IVY_CACHE}:/tmp/home/.ivy2" \
  -v "${COURSIER_CACHE}:/tmp/home/.cache/coursier" \
  -w /workspace \
  "${IMAGE}" \
  -lc '
    set -euo pipefail
    microdnf install -y git findutils tar gzip unzip which >/dev/null 2>&1
    if [ ! -f /usr/local/bin/sbt-launch.jar ]; then
      curl -fsSL https://repo1.maven.org/maven2/org/scala-sbt/sbt-launch/1.12.11/sbt-launch-1.12.11.jar -o /usr/local/bin/sbt-launch.jar
    fi
    cat > /usr/local/bin/sbt <<"SBT"
#!/usr/bin/env bash
exec java -Xms512M -Xmx4G -jar /usr/local/bin/sbt-launch.jar "$@"
SBT
    chmod +x /usr/local/bin/sbt
    cd /workspace/engine && sbt "GraalVMNativeImage / packageBin"
  '

if [[ ! -f "${REPO_ROOT}/engine/target/graalvm-native-image/chennai-engine" ]]; then
  echo "native-image build did not produce engine/target/graalvm-native-image/chennai-engine" >&2
  exit 1
fi

cp "${REPO_ROOT}/engine/target/graalvm-native-image/chennai-engine" "${OUTPUT_ABS}"
chmod +x "${OUTPUT_ABS}"
echo "Created ${OUTPUT}"

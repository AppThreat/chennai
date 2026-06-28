# chennai container image.
#
# Built on top of the appthreat/atom image, which already bundles the atom-mode
# language toolchains (Java, Scala/sbt, Node, PHP, Ruby) and the Android SDK.
# This image uses *native binaries end to end* -- it downloads the published
# chennai release (chennai + chennai-engine), the standalone non-atom backends
# (rusi, golem, dosai) and ripgrep, and installs blint (+ LLVM) for binary /
# APK / IPA analysis. Nothing is compiled here, so no GITHUB_TOKEN is needed.
#
# Everything lands under ${CHENNAI_HOME}/bin, which is placed on PATH.
ARG ATOM_IMAGE=ghcr.io/appthreat/atom:main
FROM ${ATOM_IMAGE}

LABEL maintainer="appthreat" \
      org.opencontainers.image.authors="Team AppThreat <cloud@appthreat.com>" \
      org.opencontainers.image.source="https://github.com/AppThreat/chennai" \
      org.opencontainers.image.url="https://github.com/AppThreat/chennai" \
      org.opencontainers.image.vendor="appthreat" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.title="chennai" \
      org.opencontainers.image.description="AI agent + TUI for atom and non-atom (Rust/Go/.NET/binary) data-flow analysis" \
      org.opencontainers.docker.cmd="docker run --rm -it -e ANTHROPIC_API_KEY -v \$(pwd):/app:rw -w /app ghcr.io/appthreat/chennai /app"

# CHENNAI_VERSION=latest pulls /releases/latest/download; set a tag (e.g. v0.3.0) to pin.
ARG CHENNAI_VERSION=latest
ARG CDXGEN_PLUGINS_BIN_VERSION=v2.5.1
ARG DOSAI_VERSION=v3.0.5

ENV CHENNAI_HOME=/opt/chennai \
    CHENNAI_ENGINE=/opt/chennai/bin/chennai-engine \
    NYXSTONE_LLVM_PREFIX=/usr/lib64/llvm18 \
    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING="utf-8"
ENV PATH=${CHENNAI_HOME}/bin:${PATH}

# System deps: LLVM (blint disassembly), ripgrep (chennai search tool), uv (blint install).
RUN set -eux \
    && microdnf install -y --enablerepo=epel llvm18 llvm18-devel ripgrep \
    && python3 -m pip install --no-cache-dir uv \
    && microdnf clean all

# atom-mode toolchain (also present in the base image; pinned/refreshed here):
#   cdxgen via npm (no optionals), atom + atom-parsetools via npm (need optionals),
#   atom-tools + appthreat-vulnerability-db via pip/uv.
RUN set -eux \
    && npm install -g --ignore-scripts --omit=optional @cyclonedx/cdxgen \
    && npm install -g --ignore-scripts @appthreat/atom @appthreat/atom-parsetools \
    && uv pip install --system --no-cache atom-tools "appthreat-vulnerability-db[all]" \
    && cdxgen --version && atom --help >/dev/null && atom-tools --version && vdb --help >/dev/null

# chennai native binaries (chennai + chennai-engine) from the GitHub release.
RUN set -eux \
    && mkdir -p ${CHENNAI_HOME}/bin \
    && case "$(uname -m)" in \
         x86_64|amd64)  ARCH=amd64 ;; \
         aarch64|arm64) ARCH=arm64 ;; \
         *) echo "unsupported arch $(uname -m)" >&2; exit 1 ;; \
       esac \
    && if [ "${CHENNAI_VERSION}" = "latest" ] || [ -z "${CHENNAI_VERSION}" ]; then \
         DL="https://github.com/AppThreat/chennai/releases/latest/download"; \
       else \
         DL="https://github.com/AppThreat/chennai/releases/download/${CHENNAI_VERSION}"; \
       fi \
    && curl -fSL "${DL}/chennai-linux-${ARCH}.tar.gz" -o /tmp/chennai.tgz \
    && tar -xzf /tmp/chennai.tgz --strip-components=1 -C ${CHENNAI_HOME}/bin \
    && rm -f /tmp/chennai.tgz \
    && chmod +x ${CHENNAI_HOME}/bin/chennai ${CHENNAI_HOME}/bin/chennai-engine

# Non-atom backend binaries (rusi, golem, dosai) + ripgrep fallback, into CHENNAI_HOME/bin.
COPY scripts/setup.sh ${CHENNAI_HOME}/scripts/setup.sh
RUN set -eux \
    && CDXGEN_PLUGINS_BIN_VERSION=${CDXGEN_PLUGINS_BIN_VERSION} \
       DOSAI_VERSION=${DOSAI_VERSION} \
       bash ${CHENNAI_HOME}/scripts/setup.sh --prefix ${CHENNAI_HOME}/bin --no-blint \
    # blint[extended] (nyxstone builds against LLVM); console script lands on PATH.
    && uv pip install --system --no-cache "blint[extended]"

RUN set -eux \
    && chennai --version || chennai --help >/dev/null 2>&1 || true \
    && rusi --version && golem --version && dosai --version && rg --version && blint --help >/dev/null

WORKDIR /app
ENTRYPOINT ["chennai"]

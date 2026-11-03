# Shauron execution image: the CLI plus a verified, pre-installed SAST engine.
#
# Built ahead of time on purpose: the sandbox runs with --network none, so the
# engine and the scanner must already be in the image (a download inside the
# sandbox would fail closed, which is correct but useless).
#
# Multi-arch: linux/amd64 and linux/arm64 are supported and each architecture
# gets the Trivy asset pinned to its own digest. Anything else — including a
# Windows container image — fails the build loudly instead of shipping a broken
# image. A Windows *worker host* runs the CLI against these Linux containers,
# which is a different thing and is supported.
# Bases are pinned per architecture: a single `FROM ${ARG}@<index digest>` makes
# buildx resolve the amd64 manifest for the arm64 stage, which silently produces
# an "arm64" image full of x86_64 binaries.
# no default: BuildKit injects TARGETOS/TARGETARCH for every build, and a
# default here would silently shadow them (both images came out arm64)
ARG TARGETARCH
ARG TARGETOS
FROM python:3.12-slim@sha256:1148dbb014615300fa7e713b2f94f550c0d1c69780c0805f84f093ceee34dd0b AS base-amd64
FROM python:3.12-slim@sha256:b224e2fe306f9d303251ada22961635e5b52a69c0414a0050611be31c59f5f5b AS base-arm64
FROM base-${TARGETARCH}

ARG TARGETOS
ARG TARGETARCH
ARG TRIVY_VERSION=0.76.1
ARG TRIVY_SHA256_AMD64=c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0
ARG TRIVY_SHA256_ARM64=e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f

ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BARAD_ENGINE_CACHE=/opt/barad/engines \
    HOME=/var/tmp \
    TMPDIR=/var/tmp \
    XDG_CACHE_HOME=/var/tmp/.cache

WORKDIR /app

COPY pyproject.toml README.md ./
COPY cli ./cli
# the CLI imports the repo-level integrations package by name
COPY integrations ./integrations
COPY deploy/shauron/sandbox.barad.yml ./sandbox.barad.yml

# Trivy is pinned by version *and* per-architecture digest.
RUN set -eux; \
    case "${TARGETOS}/${TARGETARCH}" in \
      linux/amd64) asset="Linux-64bit"; sha="${TRIVY_SHA256_AMD64}" ;; \
      linux/arm64) asset="Linux-ARM64"; sha="${TRIVY_SHA256_ARM64}" ;; \
      *) echo "unsupported sandbox platform ${TARGETOS}/${TARGETARCH}: the sandbox runs Linux containers only" >&2; exit 1 ;; \
    esac; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl ca-certificates; \
    curl -fsSL -o /tmp/trivy.tgz \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${asset}.tar.gz"; \
    echo "${sha}  /tmp/trivy.tgz" | sha256sum -c -; \
    tar -xzf /tmp/trivy.tgz -C /usr/local/bin trivy; \
    rm -f /tmp/trivy.tgz; \
    apt-get purge -y curl; apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/*; \
    trivy --version

# Fail the build loudly if either the CLI or the engine is missing: an image
# that only looks built is worse than no image at all.
RUN pip install --no-cache-dir --retries 5 --timeout 60 . \
 && barad --version \
 && python -c "from barad.core.engines import EngineManager; \
print(EngineManager(cache_dir='/opt/barad/engines').resolve())" \
 && test -d /opt/barad/engines \
 && chmod -R a+rX /opt/barad /app

# The sandbox runs as 65534 with a read-only root; only the tmpfs mounts write.
USER 65534:65534
WORKDIR /target
ENTRYPOINT []
CMD ["barad", "--version"]

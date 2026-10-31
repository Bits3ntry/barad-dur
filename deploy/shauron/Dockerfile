# Shauron execution image: the CLI plus a verified, pre-installed SAST engine.
#
# Built ahead of time on purpose: the sandbox runs with --network none, so the
# engine must already be in the image (a download inside the sandbox would fail
# closed, which is correct but useless).
ARG PYTHON_IMAGE=python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159
FROM ${PYTHON_IMAGE}

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

# Fail the build loudly if either the CLI or the engine is missing: an image
# that only looks built is worse than no image at all.
# Trivy is pinned by version *and* digest; the sandbox has no network, so the
# scanner must be baked in (and it must be the bytes we pinned).
ARG TRIVY_VERSION=0.76.1
ARG TRIVY_SHA256=e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && curl -fsSL -o /tmp/trivy.tgz \
    "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-ARM64.tar.gz" \
 && echo "${TRIVY_SHA256}  /tmp/trivy.tgz" | sha256sum -c - \
 && tar -xzf /tmp/trivy.tgz -C /usr/local/bin trivy \
 && rm -f /tmp/trivy.tgz \
 && apt-get purge -y curl && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/* \
 && trivy --version

RUN pip install --no-cache-dir --retries 5 --timeout 60 . \
 && barad --version \
 && python -c "from barad.core.engines import EngineManager; \
print(EngineManager(cache_dir='/opt/barad/engines').resolve())" \
 && test -d /opt/barad/engines \
 && chmod -R a+rX /opt/barad /app

# The sandbox runs as 65534 with a read-only root; only /tmp is writable.
USER 65534:65534
WORKDIR /target
ENTRYPOINT []
CMD ["barad", "--version"]

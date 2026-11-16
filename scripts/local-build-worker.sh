#!/usr/bin/env bash
# Build the two images the worker service needs.
#
#   1. shauron-scan:redteam — sandbox image from THIS repo: the barad CLI plus a
#      digest-pinned trivy. Built here, not from ../shauron.
#   2. shauron-worker:recon — the fat worker: FROM the sandbox image, plus nmap,
#      whatweb, httpx and naabu, plus the shauron source of the sibling checkout.
#      Its context is ../shauron because that is what Dockerfile.worker copies.
set -Eeuo pipefail

cd "$(dirname "$0")/.."               # repo root: Barad-d-r
ROOT=$(pwd)
SHAURON=${SHAURON_ROOT:-$ROOT/../shauron}

echo "── sandbox image (shauron-scan:redteam) from $ROOT"
docker build -f deploy/shauron/Dockerfile -t shauron-scan:redteam "$ROOT"

echo "── worker image (shauron-worker:recon) from $SHAURON"
docker build -f docker/Dockerfile.worker -t shauron-worker:recon "$SHAURON"

docker images --format '{{.Repository}}:{{.Tag}} {{.Size}}' | grep -E 'shauron-scan|shauron-worker'

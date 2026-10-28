#!/bin/sh
# Validate the GitHub workflow locally with `act` (https://github.com/nektos/act).
# Scope: this proves the workflow wiring, not GitHub-hosted infrastructure.
set -eu
cd "$(dirname "$0")/../.."
: "${ACT_IMAGE:=catthehacker/ubuntu:act-latest}"
exec act pull_request \
  --workflows .github/workflows/security.yml \
  --eventpath examples/act/pull_request.json \
  --container-architecture "$(uname -m | sed 's/arm64/linux/arm64/;s/x86_64/linux/amd64/')" \
  -P "ubuntu-latest=$ACT_IMAGE" \
  --pull=false \
  "$@"

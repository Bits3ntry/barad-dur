#!/usr/bin/env bash
# One worker always, more under load, fewer when the queue is empty.
#
#   ./scripts/deploy_shauron_worker.sh                # build + swarm + service + scaler
#   ./scripts/deploy_shauron_worker.sh --update       # push a new image to the service
#   ./scripts/deploy_shauron_worker.sh --no-scaler    # service only
#
# What is one-time: `docker swarm init`, the image build, and the two service
# creations. What is not: the scaler is a *service* with `restart: unless-stopped`,
# because a scaling loop living in a terminal is the exact failure it prevents.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SHAURON_ROOT="${SHAURON_ROOT:-$REPO_ROOT/../shauron}"
SERVICE="${SHAURON_WORKER_SERVICE:-shauron-worker}"
IMAGE="${SHAURON_WORKER_IMAGE:-shauron-worker:recon}"
PLATFORM="${SHAURON_PLATFORM:-http://host.docker.internal:8090}"
KEY="${SHAURON_BARAD_KEY:-}"

UPDATE=0
SCALER=1
for arg in "$@"; do
  case "$arg" in
    --update) UPDATE=1 ;;
    --no-scaler) SCALER=0 ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

if [[ -z "$KEY" ]]; then
  echo "SHAURON_BARAD_KEY is empty: create one in Settings → Service identities" >&2
  exit 1
fi

echo "── swarm"
if [[ "$(docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null)" != "active" ]]; then
  echo "   initialising a single-node swarm (the existing containers keep running)"
  docker swarm init >/dev/null
else
  echo "   already active"
fi

echo "── worker image"
if [[ $UPDATE -eq 0 ]]; then
  docker build -f "$REPO_ROOT/docker/Dockerfile.worker" -t "$IMAGE" "$SHAURON_ROOT"
else
  echo "   reusing $IMAGE (--update)"
fi

echo "── worker service"
if docker service inspect "$SERVICE" >/dev/null 2>&1; then
  docker service update --image "$IMAGE" --force "$SERVICE" >/dev/null
  echo "   updated $SERVICE"
else
  # --restart-condition any: a replica that dies is replaced by Swarm, so the
  # "always at least one" floor does not depend on anything we run by hand.
  # SHAURON_TOOL_RUNTIME=local is what makes the fat image socket-less.
  docker service create \
    --name "$SERVICE" \
    --replicas 1 \
    --restart-condition any \
    --env "SHAURON_PLATFORM=$PLATFORM" \
    --env "SHAURON_BARAD_KEY=$KEY" \
    --env "SHAURON_TOOL_RUNTIME=local" \
    "$IMAGE" \
    worker --loops 10000 --interval 5 --out-dir /var/tmp/runs \
    --worker-name "swarm-{{.Task.Slot}}" >/dev/null
  # No volume on purpose: the run directory is scratch, and a named volume arrives
  # owned by root, so the unprivileged worker cannot write into it. The evidence
  # that matters is already on the platform by the time the run ends.
  echo "   created $SERVICE with 1 replica (tools inside the image, no docker socket)"
fi

if [[ $SCALER -eq 1 ]]; then
  echo "── scaler service"
  ( cd "$REPO_ROOT" && SHAURON_BARAD_KEY="$KEY" SHAURON_PLATFORM="$PLATFORM" \
      docker compose -f docker/docker-compose.worker.yml up -d --build )
  echo "   the scaler owns the socket; Barad-dûr never sees it"
fi

echo
docker service ls --filter "name=$SERVICE" --format '   {{.Name}}  {{.Replicas}}  {{.Image}}'

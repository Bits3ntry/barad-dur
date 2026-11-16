#!/usr/bin/env python3
"""Scale the Shauron worker pool to the queue, with a floor of one.

Barad-dûr never touches Docker: it publishes the numbers (`GET /surface/runtime`
returns the queue, what is in flight, and the pool target computed from the
Settings policy) and this process, which is the only thing holding the Docker
socket, turns them into `docker service scale`.

Two rules make it safe to leave running:

* **Never zero.** A queue with nobody to drain it is indistinguishable from a
  broken scanner on the console, so the floor is whatever Settings says
  (`min_workers`, default 1) and Swarm's restart policy keeps those alive.
* **Slow to shrink.** Scaling down is only applied after the queue has been
  empty for `scale_down_after_s` (default 10 minutes). Workers are cheap when
  idle and expensive to start, and a pool that flaps on every quiet minute
  spends its time pulling images.

    python scripts/shauron_scaler.py --print          # what it would do, once
    python scripts/shauron_scaler.py --apply          # watch and act
    python scripts/shauron_scaler.py --apply --interval 30 --service shauron-worker
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
import time
import urllib.error
import urllib.request


def _get(url: str, key: str, timeout: float = 15.0) -> dict:
    request = urllib.request.Request(url, headers={"X-API-Key": key})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode() or "{}")


def read_pool(platform: str, key: str) -> dict:
    body = _get(f"{platform.rstrip('/')}/api/v1/surface/runtime", key)
    state = body.get("state") or {}
    pool = state.get("pool") or {}
    return {
        "target": int(pool.get("target") or 1),
        "needed": int(pool.get("needed") or 0),
        "queued": int(pool.get("queued") or 0),
        "in_flight": int(pool.get("in_flight") or 0),
        "min": int(pool.get("min") or 1),
        "max": int(pool.get("max") or 6),
        "idle_seconds": int(pool.get("idle_seconds") or 600),
        "alive": int(state.get("workers_online") or 0),
        "binding": pool.get("binding"),
    }


def _driver() -> str:
    """`compose` (one project, `--scale`) or `swarm` (one service, `scale`).

    Auto-detected: a node that is a swarm manager with the service defined is
    drifted towards Swarm; anything else is a plain Compose project. The API does
    not care which one it is — it publishes a target, not an API for Docker.
    """
    forced = (os.environ.get("SHAURON_DRIVER") or "").strip().lower()
    if forced in ("compose", "swarm"):
        return forced
    state = subprocess.run(["docker", "info", "--format", "{{.Swarm.LocalNodeState}}"],
                           capture_output=True, text=True)
    return "swarm" if (state.stdout or "").strip() == "active" else "compose"


def replicas_of(service: str) -> int:
    if _driver() == "swarm":
        result = subprocess.run(
            ["docker", "service", "inspect", service, "--format",
             "{{.Spec.Mode.Replicated.Replicas}}"],
            capture_output=True, text=True)
        if result.returncode != 0:
            raise SystemExit(f"docker service inspect {service} failed: "
                             f"{result.stderr.strip() or 'service not found'}")
        return int((result.stdout or "0").strip() or 0)
    project = os.environ.get("SHAURON_COMPOSE_PROJECT", "barad-dur")
    result = subprocess.run(
        ["docker", "ps", "-q",
         "--filter", f"label=com.docker.compose.project={project}",
         "--filter", f"label=com.docker.compose.service={service}"],
        capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"docker ps failed: {result.stderr.strip()}")
    return len([line for line in (result.stdout or "").splitlines() if line.strip()])


def scale(service: str, replicas: int, apply: bool) -> None:
    project = os.environ.get("SHAURON_COMPOSE_PROJECT", "barad-dur")
    if _driver() == "swarm":
        command = ["docker", "service", "scale", f"{service}={replicas}"]
    else:
        # --no-recreate keeps the running replicas: a scale-up must not restart
        # the worker that is in the middle of a scan.
        compose_file = os.environ.get("SHAURON_COMPOSE_FILE", "compose.yaml")
        command = ["docker", "compose", "-p", project,
                   "--project-directory", str(Path(compose_file).parent),
                   "-f", compose_file,
                   # --no-deps: scaling the pool must never touch the API or the
                   # database. A scale that restarts dependencies is a scale that
                   # can take the platform down.
                   "up", "-d", "--no-recreate", "--no-deps",
                   "--scale", f"{service}={replicas}", service]
    if not apply:
        print(f"    would run: {' '.join(command)}")
        return
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"    scale failed: {result.stderr.strip() or result.stdout.strip()}")
    else:
        print(f"    scaled to {replicas}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Scale the Shauron worker pool to the queue.")
    parser.add_argument("--platform", default=os.environ.get("SHAURON_PLATFORM", ""))
    parser.add_argument("--key", default=os.environ.get("SHAURON_BARAD_KEY", ""))
    parser.add_argument("--service", default=os.environ.get("SHAURON_WORKER_SERVICE",
                                                          "shauron-worker"))
    parser.add_argument("--interval", type=float, default=30.0)
    parser.add_argument("--apply", action="store_true",
                        help="actually call docker service scale")
    parser.add_argument("--print", dest="once", action="store_true",
                        help="print one decision and exit")
    args = parser.parse_args()

    if not args.platform or not args.key:
        raise SystemExit("SHAURON_PLATFORM and SHAURON_BARAD_KEY (or --platform/--key) "
                         "are required")

    idle_since: float | None = None
    while True:
        try:
            pool = read_pool(args.platform, args.key)
            current = replicas_of(args.service)
        except (urllib.error.URLError, OSError, ValueError, SystemExit) as error:
            # The platform being unreachable is not a reason to scale to zero:
            # the workers already up keep their leases and finish their runs.
            print(f"[{time.strftime('%H:%M:%S')}] cannot read the pool: {error}")
            if args.once:
                return 1
            time.sleep(args.interval)
            continue

        target = max(pool["min"], min(pool["max"], pool["target"]))
        busy = pool["queued"] + pool["in_flight"]

        if busy == 0 and target < current:
            idle_since = idle_since or time.time()
            idle_for = time.time() - idle_since
            if idle_for < pool["idle_seconds"]:
                print(f"[{time.strftime('%H:%M:%S')}] idle {int(idle_for)}s/"
                      f"{pool['idle_seconds']}s · holding at {current}")
                if args.once:
                    return 0
                time.sleep(args.interval)
                continue
            print(f"[{time.strftime('%H:%M:%S')}] idle {int(idle_for)}s and queue empty "
                  f"· {current} → {max(pool['min'], target)}")
        else:
            idle_since = None
            print(f"[{time.strftime('%H:%M:%S')}] queued {pool['queued']} · in flight "
                  f"{pool['in_flight']} · alive {pool['alive']} · replicas {current} "
                  f"→ target {target} ({pool['binding']})")

        if target != current:
            scale(args.service, target, args.apply)

        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""One runtime, many sessions.

The runtime is a single container with N lanes. A lane is a **process**, not a thread:
one task at a time, its own workspace, its own cwd. If a payload kills a lane, the
container and the other sessions survive.

The daemon owns nothing: it lists the queue (which the platform caps per mission), then
runs `shauron agent run <task>` and lets the CLI do the claim, the loop and the events.
That keeps the contract in one place — the platform authorizes, the CLI executes.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

PLATFORM = os.environ.get("BARAD_PLATFORM", "http://platform-api:8090").rstrip("/")
KEY = os.environ.get("BARAD_KEY") or os.environ.get("SHAURON_BARAD_KEY", "")
LANES = max(1, int(os.environ.get("FIELD_LANES", "4")))
POLL_S = max(1.0, float(os.environ.get("FIELD_POLL_S", "5")))
WORK_ROOT = Path(os.environ.get("FIELD_WORK_ROOT", "/work"))
SHAURON = os.environ.get("SHAURON_BIN", "shauron")
WORKER_NAME = os.environ.get("FIELD_WORKER_NAME", "field-runtime")
HEALTH = Path(os.environ.get("FIELD_HEALTH", "/tmp/fieldd.healthy"))
MAX_RUNTIME_S = float(os.environ.get("FIELD_TASK_TIMEOUT_S", "1800"))

_stopping = False
_running: dict[str, subprocess.Popen] = {}
#: Task id -> (failures, retry_after). A task that fails fast must not become a spin
#: loop: the same broken task retried every 5 s is noise, not work.
_failures: dict[str, tuple[int, float]] = {}
MAX_FAILURES = 3
COOLDOWN_S = 600.0


def log(event: str, **fields) -> None:
    print(json.dumps({"at": time.strftime("%Y-%m-%dT%H:%M:%S"), "event": event,
                      **fields}, ensure_ascii=False), flush=True)


def api(path: str) -> dict:
    request = urllib.request.Request(f"{PLATFORM}/api/v1{path}",
                                     headers={"X-API-Key": KEY})
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode() or "{}")


def pending() -> list[dict]:
    try:
        return api("/agent/tasks?status=queued&limit=50").get("data", [])
    except (urllib.error.URLError, TimeoutError, ValueError) as error:
        log("queue_unreachable", error=str(error))
        return []


def workspace_for(task: dict) -> Path:
    """A path per mission, never shared: two sessions must not see each other's files."""
    mission = task.get("mission_id") or "solo"
    lane = Path(WORK_ROOT) / mission
    lane.mkdir(parents=True, exist_ok=True)
    return lane


def preflight() -> str | None:
    """The image must actually carry the field loop; a missing command is fatal, not a
    retryable task failure."""
    try:
        result = subprocess.run([SHAURON, "--help"], capture_output=True, text=True,
                                timeout=30)
    except (OSError, subprocess.TimeoutExpired) as error:
        return f"cannot run {SHAURON}: {error}"
    if "agent" not in (result.stdout + result.stderr):
        return (f"{SHAURON} has no `agent` command (worker-only image?); "
                "build the runtime from the shauron checkout")
    return None


def launch(task: dict, lane: str) -> None:
    cwd = workspace_for(task)
    argv = [SHAURON, "agent", "run", task["id"], "--platform", PLATFORM,
            "--api-key", KEY, "--worker-name", lane, "--json"]
    env = {k: v for k, v in os.environ.items()
           if k in {"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR",
                    "SHAURON_TOOL_RUNTIME", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"}}
    env["HOME"] = str(Path("/tmp") / lane)
    Path(env["HOME"]).mkdir(parents=True, exist_ok=True)
    log("lane_start", lane=lane, task=task["id"], mission=task.get("mission_id"),
        kind=task.get("kind"), cwd=str(cwd))
    _running[task["id"]] = subprocess.Popen(
        argv, cwd=str(cwd), env=env, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, start_new_session=True)


def reap() -> None:
    now = time.time()
    for task_id, process in list(_running.items()):
        code = process.poll()
        if code is None:
            continue
        output = ""
        try:
            output = (process.stdout.read() or "")[-1500:] if process.stdout else ""
        except ValueError:
            pass
        log("lane_exit", task=task_id, code=code, tail=output.strip()[-600:])
        _running.pop(task_id, None)
        if code != 0:
            failures = _failures.get(task_id, (0, 0.0))[0] + 1
            wait = COOLDOWN_S if failures >= MAX_FAILURES else 0.0
            _failures[task_id] = (failures, now + wait)
            if wait:
                log("lane_cooldown", task=task_id, failures=failures,
                    seconds=int(wait))


def stop(*_args) -> None:
    global _stopping
    _stopping = True
    log("stopping", lanes=len(_running))
    for process in _running.values():
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass


def main() -> int:
    if not KEY:
        log("fatal", error="BARAD_KEY or SHAURON_BARAD_KEY is required")
        return 2
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    WORK_ROOT.mkdir(parents=True, exist_ok=True)
    log("start", platform=PLATFORM, lanes=LANES, work_root=str(WORK_ROOT))

    problem = preflight()
    if problem:
        log("fatal", error=problem)
        return 3

    once = "--once" in sys.argv
    while not _stopping:
        reap()
        HEALTH.write_text(str(int(time.time())))
        free = [f"lane-{i}" for i in range(1, LANES + 1)
                if sum(1 for p in _running.values() if p.poll() is None) < LANES]
        if free:
            now = time.time()
            for task in pending():
                if task["id"] in _running:
                    continue
                failures, retry_after = _failures.get(task["id"], (0, 0.0))
                if failures >= MAX_FAILURES and now < retry_after:
                    continue
                if not free:
                    break
                launch(task, free.pop(0))
        if once:
            break
        time.sleep(POLL_S)

    for process in _running.values():
        try:
            process.wait(timeout=MAX_RUNTIME_S)
        except subprocess.TimeoutExpired:
            process.kill()
    log("exit", remaining=len(_running))
    return 0


if __name__ == "__main__":
    sys.exit(main())

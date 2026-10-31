"""Shauron-compatible worker: claim authorized jobs and execute the CLI.

Contract (management plane side lives in the API):
  1. register + heartbeat,
  2. claim (the API re-validates the grant before leasing),
  3. start (the API answers `cancelled: true` if the job was cancelled),
  4. execute the local CLI scan for the job's `target_path`,
  5. push evidence: CycloneDX SBOM, SARIF SAST, artifact logs,
  6. report the outcome with real counters.

Nothing here invents results: if a tool is missing or the scan fails, the job
is reported `failed` with the tool's own error text.
"""
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_POLL = 5
HEARTBEAT_EVERY = 30


class WorkerError(RuntimeError):
    pass


def _call(platform_url, api_key, method, path, payload=None, timeout=30,
          worker_token=None):
    url = platform_url.rstrip("/") + path
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Accept", "application/json")
    if worker_token:
        request.add_header("X-Worker-Token", worker_token)
    else:
        request.add_header("X-API-Key", api_key)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode() or "{}"
            return response.status, json.loads(body)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode()[:300]
        raise WorkerError(f"{method} {path} -> {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise WorkerError(f"{method} {path} -> unreachable: {exc.reason}") from exc


def register(platform_url, api_key, name, capabilities, max_concurrent=1,
             worker_token=None):
    status, body = _call(platform_url, api_key, "POST", "/api/v1/orchestration/workers", {
        "name": name, "capabilities": capabilities,
        "labels": {"host": name}, "max_concurrent": max_concurrent,
        "actor": name}, worker_token=worker_token)
    return body["data"]


def heartbeat(platform_url, api_key, worker_id, worker_token=None):
    _call(platform_url, api_key, "POST",
          f"/api/v1/orchestration/workers/{worker_id}/heartbeat",
          worker_token=worker_token)


def claim(platform_url, api_key, worker_id, worker_token=None):
    _call_raw = _call(platform_url, api_key, "POST",
                      "/api/v1/orchestration/jobs/claim",
                      {"worker_id": worker_id, "actor": worker_id},
                      worker_token=worker_token)
    return _call_raw[1]


def start(platform_url, api_key, job_id, worker_id, worker_token=None):
    _, body = _call(platform_url, api_key, "POST",
                    f"/api/v1/orchestration/jobs/{job_id}/start",
                    {"actor": worker_id}, worker_token=worker_token)
    return body


def finish(platform_url, api_key, job_id, worker_id, outcome, summary,
           artifacts, error=None, worker_token=None):
    payload = {"actor": worker_id, "outcome": outcome, "summary": summary,
               "artifacts": artifacts, "error": error}
    _, body = _call(platform_url, api_key, "POST",
                    f"/api/v1/orchestration/jobs/{job_id}/result", payload,
                    timeout=60, worker_token=worker_token)
    return body


def run_scan(target_path: Path, output_dir: Path, cli_module="barad",
             timeout=900, isolate_image: str | None = None) -> dict:
    """Run the CLI scan locally, or inside an ephemeral sandbox container."""
    if isolate_image:
        from . import sandbox

        command = sandbox.build_command(
            isolate_image,
            ["barad", "run", "/target", "-O", "/out", "--json"],
            "/target", target_path, output_dir)
        try:
            returncode, stdout, stderr = sandbox.run(command, timeout=timeout)
        except sandbox.SandboxError as exc:
            raise WorkerError(f"sandbox unavailable: {exc}") from exc
        if returncode != 0:
            tail = (stderr or stdout or "")[-600:]
            raise WorkerError(f"isolated scan failed (exit {returncode}): {tail}")
        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            return {"raw_stdout_tail": (stdout or "")[-400:], "isolated": True}
    command = [sys.executable, "-m", cli_module, "run", str(target_path),
               "-O", str(output_dir), "--json"]
    completed = subprocess.run(command, capture_output=True, text=True,
                               timeout=timeout)
    if completed.returncode != 0:
        tail = (completed.stderr or completed.stdout or "")[-600:]
        raise WorkerError(f"scan failed (exit {completed.returncode}): {tail}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {"raw_stdout_tail": (completed.stdout or "")[-400:]}


def _upload_sbom(platform_url, api_key, project, version, path: Path):
    if not path.exists():
        return None
    data = path.read_bytes()
    url = (f"{platform_url.rstrip('/')}/api/v1/sbom?project={project}"
           f"&version={version}")
    request = urllib.request.Request(url, data=data, method="POST")
    if worker_token:
        request.add_header("X-Worker-Token", worker_token)
    else:
        request.add_header("X-API-Key", api_key)
    request.add_header("Content-Type", "application/octet-stream")
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read().decode() or "{}")


def _normalize_rule_id(raw: str) -> str:
    """OpenGrep emits fully-qualified rule ids (…rules.<name>); keep the name."""
    if not raw:
        return "opengrep"
    if ".rules." in raw:
        return raw.split(".rules.")[-1]
    return raw


def _relative_uri(path: str, root: Path | None) -> str:
    if root is None:
        return path
    try:
        return str(Path(path).resolve().relative_to(root.resolve()))
    except ValueError:
        return path


def _sarif_from_sast(path: Path, root: Path | None = None):
    """Adapt the CLI's sast.json (OpenGrep JSON) into one SARIF run."""
    if not path.exists():
        return None
    document = json.loads(path.read_text())
    results = []
    rules = {}
    for match in document.get("results") or document.get("matches") or []:
        rule_id = _normalize_rule_id(
            match.get("check_id") or match.get("ruleId") or "")
        extra = match.get("extra") or {}
        start = ((match.get("start") or {}).get("line")
                 or ((match.get("locations") or [{}])[0].get("start", {}) or {}).get("line"))
        uri = match.get("path") or ((match.get("locations") or [{}])[0]
                                    .get("physicalLocation", {})
                                    .get("artifactLocation", {}) or {}).get("uri")
        if not uri:
            continue
        uri = _relative_uri(uri, root)
        rules.setdefault(rule_id, {"id": rule_id,
                                   "shortDescription": {"text": extra.get("message", rule_id)}})
        results.append({
            "ruleId": rule_id,
            "level": "error" if (extra.get("severity") or "").upper() == "ERROR" else "warning",
            "message": {"text": extra.get("message") or rule_id},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": start or 1}}}],
        })
    return {"tool": {"driver": {"name": "opengrep",
                                "rules": list(rules.values())}},
            "results": results}


def _post_sarif(platform_url, api_key, project, version, run):
    payload = json.dumps({"run": run, "actor": "shauron-worker"}).encode()
    url = (f"{platform_url.rstrip('/')}/api/v1/sarif?project={project}"
           f"&version={version}")
    request = urllib.request.Request(url, data=payload, method="POST")
    if worker_token:
        request.add_header("X-Worker-Token", worker_token)
    else:
        request.add_header("X-API-Key", api_key)
    request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read().decode() or "{}")


def find_artifacts(workdir: Path) -> dict:
    """Locate the newest artifact of each kind anywhere under the workdir.

    The CLI nests runs (``<target>/<status>/scan-<id>/``), so the worker must
    not assume a flat layout — and must not silently skip uploads when a file
    is missing (callers treat an empty mapping as a failure).
    """
    found = {}
    for name in ("sbom.cdx.json", "sast.json", "execution.log",
                 "security.sanitized.json", "manifest.json"):
        matches = sorted(workdir.rglob(name),
                         key=lambda path: path.stat().st_mtime, reverse=True)
        if matches:
            found[name] = matches[0]
    return found


def _counts_from(artifacts: dict) -> dict:
    sanitized = artifacts.get("security.sanitized.json")
    if sanitized is None:
        return {}
    try:
        document = json.loads(sanitized.read_text())
    except (json.JSONDecodeError, OSError):
        return {}
    if isinstance(document, dict):
        for key in ("counts", "summary"):
            if isinstance(document.get(key), dict):
                return document[key]
    return {}


def execute_job(platform_url, api_key, worker_id, job, worker_token=None,
                isolate_image: str | None = None) -> dict:
    """Run one claimed job; returns the finish payload outcome."""
    profile = job.get("profile") or {}
    target_path = Path(profile.get("target_path") or "").expanduser()
    project = profile.get("project")
    version = profile.get("version")
    if not str(target_path) or not target_path.exists():
        finish(platform_url, api_key, job["id"], worker_id, "failed",
               {"reason": "target_path missing"}, [],
               error=f"target_path not found: {target_path}")
        return {"outcome": "failed", "reason": "target_path missing"}
    workdir = Path(profile.get("output_dir")
                   or f"/tmp/barad-worker-{job['id'][:8]}").expanduser()
    workdir.mkdir(parents=True, exist_ok=True)
    try:
        manifest = run_scan(target_path, workdir, isolate_image=isolate_image)
    except (WorkerError, subprocess.TimeoutExpired) as exc:
        finish(platform_url, api_key, job["id"], worker_id, "failed",
               {"reason": "scan_error"}, [], error=str(exc)[:900])
        return {"outcome": "failed", "reason": str(exc)[:200]}

    artifacts_on_disk = find_artifacts(workdir)
    if not artifacts_on_disk:
        finish(platform_url, api_key, job["id"], worker_id, "failed",
               {"reason": "no_artifacts"}, [],
               error=f"scan produced no artifacts under {workdir}")
        return {"outcome": "failed", "reason": "no_artifacts"}

    summary = {"run_id": manifest.get("run_id"),
               "project": (manifest.get("project") or {}).get("name"),
               "version": ((manifest.get("application_version") or {}).get("value")
                           or version),
               "counts": manifest.get("counts") or _counts_from(artifacts_on_disk)}
    ingested = {}
    try:
        if project and version:
            sbom_path = artifacts_on_disk.get("sbom.cdx.json")
            if sbom_path is not None:
                sbom = _upload_sbom(platform_url, api_key, project, version,
                                    sbom_path)
                if sbom is not None:
                    ingested["sbom"] = sbom.get("counters") or sbom
            sarif_path = artifacts_on_disk.get("sast.json")
            if sarif_path is not None:
                sarif = _sarif_from_sast(sarif_path, target_path)
                if sarif and sarif["results"]:
                    ingested["sarif"] = _post_sarif(platform_url, api_key, project,
                                                    version, sarif)
    except Exception as exc:  # ingest failures are reported, never swallowed
        ingested["error"] = str(exc)[:400]

    artifacts = [{"kind": "manifest", "content": json.dumps(summary)[:200000]}]
    log = artifacts_on_disk.get("execution.log")
    if log is not None:
        artifacts.append({"kind": "log",
                          "content": log.read_text(errors="replace")[-50000:]})
    outcome = "failed" if ingested.get("error") else "succeeded"
    finish(platform_url, api_key, job["id"], worker_id, outcome,
           {**summary, "ingested": ingested}, artifacts,
           error=ingested.get("error"))
    return {"outcome": outcome, "summary": summary, "ingested": ingested}


def serve(platform_url, api_key, name="shauron-worker", capabilities=None,
          max_concurrent=1, once=False, poll=DEFAULT_POLL, limit=None,
          worker_token=None, isolate_image: str | None = None):
    """Register, then poll for jobs until stopped (or `limit` jobs)."""
    capabilities = capabilities or ["vulnerability_analysis"]
    worker = register(platform_url, api_key, name, capabilities, max_concurrent)
    worker_id = worker["id"]
    handled = 0
    last_heartbeat = time.time()
    while True:
        if time.time() - last_heartbeat > HEARTBEAT_EVERY:
            heartbeat(platform_url, api_key, worker_id, worker_token)
            last_heartbeat = time.time()
        body = claim(platform_url, api_key, worker_id, worker_token)
        job = body.get("data")
        if not job:
            if once or (limit is not None and handled >= limit):
                return {"worker": worker_id, "handled": handled,
                        "rejected": body.get("rejected")}
            time.sleep(poll)
            continue
        started = start(platform_url, api_key, job["id"], worker_id, worker_token)
        if started.get("cancelled"):
            handled += 1
            continue
        execute_job(platform_url, api_key, worker_id, job, worker_token,
                    isolate_image=isolate_image)
        handled += 1
        if once or (limit is not None and handled >= limit):
            return {"worker": worker_id, "handled": handled}

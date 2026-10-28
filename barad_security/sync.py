"""Deferred publication: publish preserved evidence later, never rescan.

`sync` reuses the artifacts already on disk from a finished run. It does not
invoke Trivy, does not recompute decisions and does not create a new run id: it
only retries the publications that were left PENDING or FAILED.
"""
import json
from pathlib import Path

from .errors import BaradError, UsageError
from .evidence import RunStore, utc_timestamp
from .integrations import base as pub
from .integrations.barad_dur import BaradDurPublisher
from .integrations.defectdojo import DefectDojoPublisher
from .integrations.dependency_track import DependencyTrackPublisher
from .logs import Logger, Redactor

ADAPTERS = {adapter.service: adapter for adapter in
            (BaradDurPublisher, DependencyTrackPublisher, DefectDojoPublisher)}

RETRYABLE = (pub.PENDING, pub.FAILED, "PENDING", "FAILED")


def _redactor(config, environ):
    values = []
    for block in ("barad_dur", "dependency_track", "defectdojo"):
        for key in ("token_env", "endpoint_env"):
            name = config.get(f"integrations.{block}.{key}")
            if name:
                values.append(environ.get(name) or "")
    return Redactor(values)


def load_run(config, run_id):
    store = RunStore(config, run_id)
    manifest_path = store.artifact_path("manifest.json")
    if not manifest_path.is_file():
        raise UsageError(f"unknown run: {run_id} (no manifest at {manifest_path})")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    return store, manifest


def build_context(config, store, manifest):
    artifacts = {}
    for path in sorted(store.run_dir.iterdir()):
        if path.is_file() and path.name not in ("checksums.sha256",):
            artifacts[path.name] = path
    sbom = store.artifact_path("sbom.cdx.json")
    report = store.artifact_path("trivy-report.sanitized.json")
    if not report.is_file():
        raw = store.artifact_path("trivy-report.json")
        if raw.is_file():
            from .sanitize import write_sanitized_report
            write_sanitized_report(raw, report)
    return pub.PublishContext(
        run_id=manifest["run_id"],
        event=manifest.get("event") or "local",
        service=manifest.get("service") or config.get("project.service"),
        project=manifest.get("project") or config.get("project.name"),
        version=manifest.get("application_version"),
        git=manifest.get("git") or {},
        run_dir=store.run_dir,
        artifacts=artifacts,
        manifest=manifest,
        sbom_path=sbom if sbom.is_file() else None,
        report_path=report if report.is_file() else None,
        raw_report_path=store.artifact_path("trivy-report.json"),
        retry_of=manifest["run_id"],
    )


def _pending_services(manifest, pending_entry):
    if pending_entry and pending_entry.get("services"):
        return list(pending_entry["services"])
    services = []
    for name, step in (manifest.get("publications") or {}).items():
        if name.startswith("_"):
            continue
        if step.get("status") in RETRYABLE:
            services.append(name)
    return services


def _ledger_key(store, service, context):
    from .orchestration import _sha256

    digest = "-"
    if service == "dependency_track" and context.sbom_path:
        digest = _sha256(context.sbom_path)
    elif context.report_path:
        digest = _sha256(context.report_path)
    return ":".join([service, context.service, context.publish_target or context.event,
                     str(context.version or ""), digest[:16]])


def sync_run(config, run_id, *, environ=None, logger=None):
    """Retry the pending publications of one finished run."""
    environ = dict(environ or {})
    store, manifest = load_run(config, run_id)
    logger = logger or Logger(run_id, path=store.log_path, redactor=_redactor(config, environ))
    pending_entry = next((entry for entry in store.pending_entries() if entry.get("run_id") == run_id), None)
    services = _pending_services(manifest, pending_entry)
    if not services:
        logger.info("sync", "nothing_to_sync", {"run_id": run_id})
        return {"run_id": run_id, "services": {}, "resolved": True, "already_published": True}

    context = build_context(config, store, manifest)
    results = {}
    unresolved = []
    for service in services:
        adapter = ADAPTERS.get(service)(config, logger)
        if adapter is None or not adapter.enabled():
            results[service] = {"status": pub.SKIPPED, "reason": "integration_disabled"}
            continue
        plan = (manifest.get("decisions", {}).get("publications", {}) or {}).get(service, {})
        context.publish_target = plan.get("target")
        context.required = bool(plan.get("required"))
        context.known_external_ids = _known_ids(config, store, manifest, service)
        key = _ledger_key(store, service, context)
        previous = store.ledger_get(key)
        if previous and previous.get("status") == pub.PUBLISHED:
            results[service] = {"status": pub.DUPLICATE, "reason": "already_published"}
            continue
        result = adapter.publish(context)
        payload = result.public()
        results[service] = payload
        manifest.setdefault("publications", {})[service] = payload
        manifest.setdefault("steps", {})[service] = payload
        if result.status in (pub.PUBLISHED, pub.DUPLICATE):
            store.ledger_put(key, {"status": pub.PUBLISHED, "run_id": run_id,
                                   "external_ids": result.external_ids,
                                   "recorded_at": utc_timestamp(), "synced": True})
        else:
            unresolved.append(service)

    manifest.setdefault("sync", []).append({"synced_at": utc_timestamp(),
                                            "services": list(results),
                                            "resolved": not unresolved})
    store.write_json("manifest.json", manifest)
    store.write_json("publication.json", {
        "run_id": run_id,
        "publications": {name: value for name, value in (manifest.get("publications") or {}).items()
                         if not name.startswith("_")},
        "state": (manifest.get("publications") or {}).get("_state", {}),
        "sync": manifest.get("sync", []),
    })
    if unresolved:
        store.enqueue_pending({"reason": "still_unresolved", "status": pub.PENDING,
                               "services": unresolved, "artifacts": sorted(context.artifacts)})
    else:
        store.drop_pending(run_id)
    logger.info("sync", "finished", {"run_id": run_id, "resolved": not unresolved,
                                     "services": list(results)})
    return {"run_id": run_id, "services": results, "resolved": not unresolved}


def _known_ids(config, store, manifest, service):
    ids = {}
    version = manifest.get("application_version")
    if service == "dependency_track":
        record = store.inventory_record(manifest.get("service"), version) if version else None
        if record:
            ids["release_sbom_sha256"] = record.get("sbom_sha256")
            ids["release_component_fingerprint"] = record.get("component_fingerprint")
        sbom = store.artifact_path("sbom.cdx.json")
        if sbom.is_file():
            from .orchestration import _sha256
            ids["sbom_sha256"] = _sha256(sbom)
    if service == "defectdojo":
        ledger = store.ledger_get(f"defectdojo:{manifest.get('service')}:test")
        if ledger and ledger.get("external_ids", {}).get("test"):
            ids["test"] = ledger["external_ids"]["test"]
    return ids


def sync_pending(config, *, environ=None):
    """Sync every queued run; returns one result per run."""
    environ = dict(environ or {})
    probe = RunStore(config, "sync")
    outcomes = []
    for entry in probe.pending_entries():
        run_id = entry.get("run_id")
        try:
            outcomes.append(sync_run(config, run_id, environ=environ))
        except BaradError as error:
            outcomes.append({"run_id": run_id, "resolved": False, "error": error.message})
    return outcomes

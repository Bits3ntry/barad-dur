"""One scan: Trivy JSON and CycloneDX on every invocation, kept as local evidence.

The command reuses `barad.core.TrivyRunner`, the CycloneDX validator, Git
context and version resolution. It never treats a missing report, a failed
scanner, or an unusable inventory as success, and it never deletes artifacts it
managed to produce.
"""
import json
import platform
from dataclasses import dataclass
from pathlib import Path

from .core import MANIFEST_SCHEMA_VERSION, __version__ as SECURITY_VERSION
from .core.errors import ScannerError
from .core.evidence import generate_run_id, sha256_file, utc_timestamp
from .core.logs import Logger, Redactor
from .core.sanitize import sanitize_trivy_report
from .core.sbom import validate as validate_sbom
from .core.opengrep import OpenGrepRunner
from .core.trivy import TrivyRunner
from .core.versioning import resolve_version

from . import __version__
from .core.inventory import BASIS, compare, fingerprint
from .store import ScanStore

REPORT = "security.json"
SANITIZED_REPORT = "security.sanitized.json"
SBOM = "sbom.cdx.json"
SAST_REPORT = "sast.json"


@dataclass
class ScanResult:
    exit_code: int
    manifest: dict
    run_dir: Path
    error: str = None


def run_scan(settings, *, target_type, target_value, git_context, name_source,
             environ=None, application_version=None):
    config = settings.security
    workspace = settings.workspace or settings.root
    project_name = settings.document["project"]["name"]
    run_id = generate_run_id("scan")
    application_version = (application_version or resolve_version(
        config, environ=environ if environ is not None else settings.environ
    )).public()
    store = ScanStore(workspace, settings.document["output"]["directory"], run_id,
                      project=project_name,
                      version=application_version["value"]).prepare()
    logger = Logger(run_id, path=store.log_path, stream=None,
                    redactor=Redactor(settings.secret_values()))
    started = utc_timestamp()
    logger.info("scan", "started", {"target_type": target_type, "target": target_value})

    trivy = TrivyRunner(config, logger, repo_root=settings.root)
    opengrep = OpenGrepRunner(config, logger, repo_root=settings.root)
    scan = {
        "status": "RUNNING",
        "started_at": started,
        "finished_at": None,
        "target": {"type": target_type, "value": target_value},
        "scanner_versions": {"barad": __version__, "trivy": None, "opengrep": None},
        "engines": {},
        "counts": {},
        "errors": [],
        "warnings": [],
        "redaction": None,
    }
    problems = []
    preflight_failed = False
    json_ok = sbom_ok = sast_ok = False

    try:
        trivy.preflight()
    except ScannerError as error:
        preflight_failed = True
        _problem(problems, scan, error.kind, error.message)
        logger.error("trivy", "preflight_failed", {"detail": error.message})
    else:
        try:
            report = trivy.scan_json(store.artifact_path(REPORT))
        except ScannerError as error:
            _problem(problems, scan, error.kind, error.message)
        else:
            scan["counts"] = dict(report.counts)
            scan["warnings"].extend(report.warnings)
            scan["scanner_versions"]["trivy"] = report.version
            json_ok = report.successful
            if not json_ok:
                detail = (report.error or {}).get("detail") or "no valid JSON report"
                _problem(problems, scan, "scan_failed", detail)
        try:
            inventory_outcome = trivy.generate_sbom(store.artifact_path(SBOM))
        except ScannerError as error:
            _problem(problems, scan, error.kind, error.message)
        else:
            scan["scanner_versions"]["trivy"] = (
                scan["scanner_versions"]["trivy"] or inventory_outcome.version
            )
            sbom_ok = inventory_outcome.successful
            if not sbom_ok:
                detail = (inventory_outcome.error or {}).get("detail") or "no CycloneDX inventory"
                _problem(problems, scan, "inventory_failed", detail)

    try:
        opengrep.preflight()
    except ScannerError as error:
        _problem(problems, scan, error.kind, error.message)
        logger.error("opengrep", "preflight_failed", {"detail": error.message})
    else:
        try:
            sast = opengrep.scan_json(store.artifact_path(SAST_REPORT))
        except ScannerError as error:
            _problem(problems, scan, error.kind, error.message)
        else:
            scan["scanner_versions"]["opengrep"] = sast.version
            scan["counts"]["sast"] = dict(sast.counts)
            engine = dict((sast.parameters or {}).get("engine") or {})
            if engine:
                # Provenance of the verified binary: version, platform and digest.
                scan["engines"]["opengrep"] = engine
            sast_ok = sast.successful
            if not sast_ok:
                detail = (sast.error or {}).get("detail") or "no valid OpenGrep JSON report"
                _problem(problems, scan, "sast_failed", detail)

    unprotected = store.protect_evidence()
    scan["evidence_protection"] = {
        "directories": "0700",
        "files": "0600",
        "unprotected": unprotected,
    }

    report_path = store.artifact_path(REPORT)
    if report_path.is_file():
        document = _load_json(report_path)
        if document is None:
            _problem(problems, scan, "report_unreadable", "Trivy JSON report is not JSON")
        else:
            sanitized, scan["redaction"] = sanitize_trivy_report(document)
            store.write_json(SANITIZED_REPORT, sanitized)

    inventory = {
        "fingerprint": None,
        "basis": BASIS,
        "target": {"type": target_type, "value": target_value},
        "components": 0,
        "comparison": "unavailable",
        "previous": None,
        "publication": {"claimed": False, "basis": "local_snapshot_only"},
    }
    if sbom_ok:
        document = _load_json(store.artifact_path(SBOM))
        if document is None:
            _problem(problems, scan, "inventory_unreadable", "CycloneDX inventory is not JSON")
        else:
            validation = validate_sbom(document)
            inventory["components"] = validation.summary.get("components", 0)
            if validation.ok:
                current = fingerprint(document, target_type=target_type,
                                       target=target_value)
                inventory["fingerprint"] = current
                record = store.inventory_record(project_name, _target_key(target_type, target_value))
                inventory["comparison"], inventory["previous"] = compare(
                    record, target_type=target_type, target=target_value, current=current
                )
            else:
                for issue in validation.problems:
                    _problem(problems, scan, issue["code"], issue["detail"])

    if json_ok and sbom_ok and sast_ok and inventory["fingerprint"]:
        status, scan_status = "completed", "SUCCESS"
    elif json_ok and sbom_ok and sast_ok:
        status, scan_status = "incomplete", "INCOMPLETE"
    else:
        status, scan_status = "failed", "FAILED"
    scan["status"] = scan_status
    scan["finished_at"] = utc_timestamp()
    logger.info("scan", "finished", {
        "status": status, "json": json_ok, "sbom": sbom_ok, "sast": sast_ok,
    })

    if status == "completed":
        store.record_inventory(project_name, _target_key(target_type, target_value), {
            "inventory_fingerprint": inventory["fingerprint"],
            "inventory_basis": BASIS,
            "components": inventory["components"],
            "target_type": target_type,
            "target": target_value,
            "scanner": {"name": "trivy", "version": scan["scanner_versions"]["trivy"]},
            "sbom_sha256": store.sha256(SBOM),
            "run_id": run_id,
            "recorded_at": utc_timestamp(),
        })

    artifacts = {}
    for name in (REPORT, SANITIZED_REPORT, SBOM, SAST_REPORT, "execution.log"):
        path = store.artifact_path(name)
        if path.is_file():
            artifacts[name] = {
                "path": _display(path, workspace),
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
                "sensitivity": "local_only" if name in (REPORT, SAST_REPORT, "execution.log")
                else "redacted" if name == SANITIZED_REPORT else "shareable",
            }

    git = _git_summary(git_context)
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "tool": {"name": "barad", "version": __version__},
        "run_id": run_id,
        "run": {"id": run_id, "directory": _display(store.run_dir, workspace)},
        "state": {"directory": _display(store.state_dir, workspace),
                  "file": "local-inventory.json", "publication": "not_asserted"},
        "status": status,
        "source": {
            "kind": "local_cli",
            "target_type": target_type,
            "target": target_value,
            "git": "available" if git["available"] else "unavailable",
        },
        "project": {
            "name": project_name,
            "name_source": name_source,
            "ecosystems": list(settings.ecosystems),
            "target": {"type": target_type, "value": target_value},
        },
        "application_version": application_version,
        "commit": git["commit"],
        "git": git,
        "scan": scan,
        "inventory": inventory,
        "artifacts": artifacts,
        "config": {
            "source": _display(settings.source, workspace) if settings.source else None,
            "fingerprint": config.fingerprint(),
        },
        "environment": {
            "python": platform.python_version(),
            "platform": platform.system(),
            "trivy_runner": config.get("trivy.runner"),
        },
        "problems": problems,
    }
    store.write_json("manifest.json", manifest)
    store.write_checksums(list(artifacts) + ["manifest.json"])
    store.protect_evidence()

    error = None
    if status == "failed":
        if preflight_failed and problems:
            error = problems[0]["detail"]
        else:
            detail = next((item["detail"] for item in scan["errors"]
                           if item.get("detail")), "scan did not complete")
            error = f"scan failed: {detail}"
    elif status == "incomplete":
        detail = next((item["code"] for item in problems if item.get("code")),
                      "inventory incomplete")
        error = f"inventory incomplete: {detail}"
    return ScanResult(0 if status == "completed" else 1, manifest, store.run_dir, error)


def _problem(problems, scan, code, detail):
    entry = {"code": code, "detail": detail}
    problems.append(entry)
    scan["errors"].append(dict(entry))


def _target_key(target_type, target_value):
    return f"{target_type}:{target_value}"


def _load_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _display(path, root):
    path = Path(path).resolve()
    try:
        return path.relative_to(Path(root).resolve()).as_posix()
    except ValueError:  # paths outside the workspace stay fully visible
        return str(path)


def _git_summary(context):
    if context is None:
        return {"available": False, "repository_root": None, "repository": None,
                "branch": None, "commit": None, "event": None, "base_sha": None,
                "problems": []}
    return {
        "available": context.available,
        "repository_root": str(context.repository_root) if context.available else None,
        "repository": Path(context.repository_root).name if context.available else None,
        "branch": context.branch,
        "commit": context.commit_sha,
        "event": context.event,
        "base_sha": context.base_sha,
        "problems": list(context.problems),
    }

"""The security run: one code path for CLI, Git hooks, act and GitHub Actions.

Order is the contract: load configuration, detect Git context, detect changes,
run Trivy (always), evaluate the SBOM rule, generate and validate the SBOM, keep
evidence, then publish through decoupled adapters. A publication failure never
destroys an analysis result; a scanner failure is reported as a technical error
and is never confused with findings.
"""
import json
import os
import platform
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from . import MANIFEST_SCHEMA_VERSION, __version__
from .changes import detect_changes
from .config import ConfigError
from .decisions import evaluate
from .errors import BaradError, ScannerError
from .evidence import FAILED, RUNNING, SKIPPED, SUCCESS, RunStore, generate_run_id, utc_timestamp
from .gitctx import detect_git_context
from .integrations import base as pub
from .integrations.barad_dur import BaradDurPublisher
from .integrations.defectdojo import DefectDojoPublisher
from .integrations.dependency_track import DependencyTrackPublisher
from .logs import Logger, Redactor, utc_now
from .sbom import validate as validate_sbom
from .sanitize import write_sanitized_report
from .trivy import TrivyRunner
from .versioning import resolve_version

ADAPTERS = (BaradDurPublisher, DependencyTrackPublisher, DefectDojoPublisher)
SECRET_ENV_KEYS = ("token_env", "endpoint_env")


def detect_source(environ=None):
    env = environ or os.environ
    if env.get("GITHUB_ACTIONS") == "true":
        return "github"
    if env.get("ACT"):
        return "act"
    return "local"


@dataclass
class RunOutcome:
    run_id: str
    status: str
    exit_code: int
    manifest: dict
    run_dir: Path
    problems: list = field(default_factory=list)

    def summary(self):
        result = self.manifest.get("result", {})
        return {
            "run_id": self.run_id,
            "status": self.status,
            "exit_code": self.exit_code,
            "scan_successful": result.get("scan_successful"),
            "generate_sbom": self.manifest.get("decisions", {}).get("generate_sbom"),
            "sbom_reason": self.manifest.get("decisions", {}).get("sbom_reason"),
            "counts": self.manifest.get("security", {}).get("counts", {}),
            "run_dir": str(self.run_dir),
            "problems": self.problems,
        }


class SecurityRunner:
    def __init__(self, config, *, event=None, base_ref=None, version=None, run_id=None,
                 source=None, environ=None):
        self.config = config
        self.environ = dict(environ if environ is not None else os.environ)
        self.event = event
        self.base_ref = base_ref or config.get("detection.base_ref")
        self.version_override = version
        self.requested_run_id = run_id
        self.source = source or detect_source(self.environ)

    # -- entry point -------------------------------------------------------
    def run(self):
        self._check_execution_enabled()
        run_id = self.requested_run_id or generate_run_id(self.source)
        store = RunStore(self.config, run_id).prepare()
        logger = Logger(
            run_id,
            path=store.log_path,
            level=self.config.get("execution.log_level", "INFO"),
            redactor=self._redactor(),
        )
        started = utc_now()
        logger.info("run", "workflow_started", {
            "source": self.source, "event": self.event or "inferred",
            "config": str(self.config.source.name) if self.config.source else None,
            "config_fingerprint": self.config.fingerprint()[:16],
        })

        manifest = {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "run_id": run_id,
            "source": self.source,
            "event": None,
            "project": self.config.get("project.name"),
            "service": self.config.get("project.service"),
            "application_version": None,
            "repository": None,
            "git": {},
            "timestamps": {"started_at": utc_timestamp(started), "finished_at": None},
            "changes": {},
            "decisions": {},
            "steps": {},
            "security": {"counts": {}, "scan_successful": False},
            "publications": {},
            "artifacts": {},
            "environment": self._environment(),
            "config": {"fingerprint": self.config.fingerprint(), "source": self._config_name(),
                       "effective": self.config.public()},
            "problems": [],
            "tool": {"name": "barad-security", "version": __version__},
        }
        state = {"technical_failure": False, "required_failure": False, "findings": 0,
                 "published_any": False, "publication_failed": False, "publication_deferred": False}

        try:
            context = detect_git_context(self.config.repo_root, event=self.event,
                                         base_ref=self.base_ref, environ=self.environ)
        except BaradError as error:
            context = None
            manifest["problems"].append({"code": error.kind, "detail": error.message})

        if context is not None:
            manifest["event"] = context.event
            manifest["git"] = context.public()
            manifest["repository"] = _repository_name(context, self.config)
            manifest["problems"].extend(context.problems)
            for problem in context.problems:
                logger.warning("git", problem["code"], {"detail": problem.get("detail")})
        else:
            manifest["event"] = self.event or "local"

        version_info = self._resolve_version(context)
        manifest["application_version"] = version_info.value

        report = detect_changes(self.config, context, version_info) if context else _empty_report()
        manifest["changes"] = report.public()
        inventory_version = self._inventory_version(version_info)
        service_name = self.config.get("project.service")
        self._prior_inventory = store.inventory_record(service_name, inventory_version)
        inventory_present = bool(self._prior_inventory and self._prior_inventory.get("sbom_sha256"))
        decisions = evaluate(self.config, context, report, version_info,
                            inventory_present=inventory_present) if context else None
        if decisions is None:
            raise BaradError("cannot decide without a Git context",
                             details={"problems": manifest["problems"]})
        manifest["decisions"] = decisions.public()
        store.write_json("decisions.json", decisions.public())
        logger.info("decision", "plan_ready", {
            "run_trivy": decisions.run_trivy,
            "generate_sbom": decisions.generate_sbom,
            "sbom_reason": decisions.sbom_reason,
            "files_changed": len(report.files_changed),
        })

        artifacts = []
        trivy = TrivyRunner(self.config, logger, repo_root=self.config.repo_root)
        scan_ok = self._run_trivy(trivy, store, manifest, logger, state)
        if scan_ok:
            artifacts.append("trivy-report.json")
        sanitized_path = None
        if scan_ok:
            sanitized_path = self._sanitize_report(store, manifest, logger)
            artifacts.append("trivy-report.sanitized.json")

        sbom_ok = False
        sbom_summary = None
        if scan_ok and decisions.generate_sbom:
            sbom_ok, sbom_summary = self._run_sbom(trivy, store, manifest, logger, state)
            if sbom_ok:
                artifacts.append("sbom.cdx.json")
                self._record_inventory(store, manifest, sbom_summary, logger)

        if scan_ok:
            context_for_publish = self._build_context(context, store, manifest, version_info,
                                                      sanitized_path, sbom_ok, sbom_summary)
            self._publish(context_for_publish, store, manifest, logger, state, decisions)

        result_status = self._finish(store, manifest, logger, state, artifacts, started)
        exit_code = self._exit_code(state)
        if self.config.get("artifacts.preserve_reports", True) is False:
            self._discard_reports(store, logger, state)
        else:
            store.write_checksums(self._evidentiary_files(store))
        if self.config.get("artifacts.preserve_logs", True) is False:
            try:
                store.log_path.unlink(missing_ok=True)
            except OSError:
                pass
        return RunOutcome(run_id=run_id, status=result_status, exit_code=exit_code,
                          manifest=manifest, run_dir=store.run_dir,
                          problems=manifest["problems"])

    # -- steps -------------------------------------------------------------
    def _check_execution_enabled(self):
        if self.source in ("local", "act") and not self.config.get("execution.local_enabled", True):
            raise ConfigError("local execution is disabled by execution.local_enabled")
        if self.source == "github" and not self.config.get("execution.github_enabled", True):
            raise ConfigError("GitHub execution is disabled by execution.github_enabled")

    def _resolve_version(self, context):
        if self.version_override:
            from .versioning import VersionInfo
            return VersionInfo(value=str(self.version_override).strip(), source="cli_override")
        version_info = resolve_version(self.config, environ=self.environ)
        if context and context.event == "release" and context.tag and not version_info.resolved:
            from .versioning import VersionInfo
            return VersionInfo(value=context.tag.lstrip("v"), source="git_tag_event")
        return version_info

    def _inventory_version(self, version_info):
        if version_info and version_info.value:
            return version_info.value
        return self.config.get("integrations.dependency_track.development_version", "main")

    def _run_trivy(self, trivy, store, manifest, logger, state):
        step = {"status": RUNNING, "artifact": "trivy-report.json"}
        manifest["steps"]["trivy"] = step
        try:
            trivy.preflight()
        except ScannerError as error:
            return self._scanner_failure(store, manifest, logger, state, error)
        try:
            outcome = trivy.scan_json(store.artifact_path("trivy-report.json"))
        except ScannerError as error:
            return self._scanner_failure(store, manifest, logger, state, error)
        payload = outcome.public()
        payload["status"] = SUCCESS if outcome.successful else FAILED
        step.update(payload)
        manifest["security"]["counts"] = outcome.counts
        manifest["security"]["scan_successful"] = outcome.successful
        manifest["security"]["scan_type"] = trivy.scan_type
        manifest["security"]["target"] = trivy.scan_target()
        manifest["security"]["trivy_version"] = outcome.version
        manifest["security"]["findings_detected"] = bool(
            outcome.counts.get("total") or outcome.counts.get("secrets")
            or outcome.counts.get("misconfigurations"))
        if not outcome.successful:
            logger.error("trivy", "technical_failure", {"error": outcome.error})
            manifest["problems"].append({"code": "trivy_failed", "detail": outcome.error})
            state["technical_failure"] = True
            return False
        state["findings"] = (outcome.counts.get("total", 0) + outcome.counts.get("secrets", 0)
                             + outcome.counts.get("misconfigurations", 0))
        return True

    def _scanner_failure(self, store, manifest, logger, state, error):
        manifest["steps"]["trivy"] = {"status": FAILED, "artifact": None,
                                      "error": {"code": error.kind, "detail": error.message}}
        manifest["security"]["scan_successful"] = False
        manifest["problems"].append({"code": error.kind, "detail": error.message})
        logger.error("trivy", "technical_failure", {"detail": error.message})
        state["technical_failure"] = True
        return False

    def _sanitize_report(self, store, manifest, logger):
        summary = write_sanitized_report(store.artifact_path("trivy-report.json"),
                                        store.artifact_path("trivy-report.sanitized.json"))
        manifest["security"]["outbound_redaction"] = summary
        if summary["redacted_fields"]:
            logger.warning("evidence", "secret_evidence_redacted", {"fields": summary["redacted_fields"]})
        return store.artifact_path("trivy-report.sanitized.json")

    def _run_sbom(self, trivy, store, manifest, logger, state):
        step = {"status": RUNNING, "artifact": "sbom.cdx.json"}
        manifest["steps"]["sbom"] = step
        try:
            outcome = trivy.generate_sbom(store.artifact_path("sbom.cdx.json"))
        except ScannerError as error:
            step.update({"status": FAILED, "error": {"code": error.kind, "detail": error.message}})
            manifest["problems"].append({"code": "sbom_generation_failed", "detail": error.message})
            state["technical_failure"] = True
            return False, None
        payload = outcome.public()
        payload["status"] = SUCCESS if outcome.successful else FAILED
        step.update(payload)
        if not outcome.successful:
            state["technical_failure"] = True
            return False, None
        try:
            document = json.loads(store.artifact_path("sbom.cdx.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            step.update({"status": FAILED, "error": {"code": "sbom_unreadable", "detail": str(error)}})
            manifest["problems"].append({"code": "sbom_unreadable", "detail": str(error)})
            state["technical_failure"] = True
            return False, None
        validation = validate_sbom(document)
        step["validation"] = validation.public()
        manifest["sbom"] = validation.public()
        for warning in validation.warnings:
            logger.warning("sbom", warning["code"], {"detail": warning["detail"]})
        if not validation.ok:
            step["status"] = FAILED
            manifest["problems"].append({"code": "sbom_invalid", "detail": validation.problems})
            logger.error("sbom", "invalid", {"problems": validation.problems})
            state["technical_failure"] = True
            return False, None
        logger.info("sbom", "validated", {"components": validation.summary["components"],
                                          "purls": validation.summary["components_with_purl"]})
        return True, validation.public()

    def _record_inventory(self, store, manifest, sbom_summary, logger):
        service = self.config.get("project.service")
        version = manifest["application_version"] or self._inventory_version(None)
        if not version:
            return
        path = store.artifact_path("sbom.cdx.json")
        digest = store.sha256("sbom.cdx.json")
        store.record_inventory(service, version, {
            "sbom_sha256": digest,
            "components": sbom_summary["summary"]["components"],
            "component_fingerprint": _component_fingerprint(path),
            "run_id": manifest["run_id"],
            "recorded_at": utc_timestamp(),
        })
        logger.info("inventory", "recorded", {"service": service, "version": version,
                                              "sbom_sha256": digest[:16]})

    # -- publications ------------------------------------------------------
    def _build_context(self, context, store, manifest, version_info, sanitized_path, sbom_ok, sbom_summary):
        artifacts = {}
        for name in ("manifest.json", "decisions.json", "trivy-report.json",
                     "trivy-report.sanitized.json", "sbom.cdx.json", "execution.log",
                     "checksums.sha256"):
            path = store.artifact_path(name)
            if path.is_file():
                artifacts[name] = path
        return pub.PublishContext(
            run_id=manifest["run_id"],
            event=manifest["event"],
            service=manifest["service"],
            project=manifest["project"],
            version=manifest["application_version"],
            git=manifest["git"],
            run_dir=store.run_dir,
            artifacts=artifacts,
            manifest=manifest,
            sbom_path=store.artifact_path("sbom.cdx.json") if sbom_ok else None,
            report_path=sanitized_path,
            raw_report_path=store.artifact_path("trivy-report.json"),
            required=False,
        )

    def _publish(self, context, store, manifest, logger, state, decisions):
        plan = decisions.publications
        inventory = self._inventory_ids(store, manifest)
        for adapter_class in ADAPTERS:
            adapter = adapter_class(self.config, logger)
            service = adapter.service
            step_plan = plan.get(service, {"action": "skip", "reason": "not_planned"})
            if not adapter.enabled() or step_plan.get("action") != "publish":
                manifest["steps"][service] = {"status": SKIPPED, "reason": step_plan.get("reason",
                                                                                        "integration_disabled")}
                logger.info(service, "publication_skipped", {"reason": step_plan.get("reason")})
                continue
            context.publish_target = step_plan.get("target")
            context.required = bool(step_plan.get("required"))
            context.known_external_ids = dict(inventory.get(service, {}))
            ledger_key = self._ledger_key(service, context)
            previous = store.ledger_get(ledger_key)
            if previous and previous.get("status") == pub.PUBLISHED:
                manifest["steps"][service] = {
                    "status": "DUPLICATE", "reason": "already_published",
                    "external_ids": previous.get("external_ids", {}),
                    "ledger_key": ledger_key,
                }
                manifest["publications"][service] = dict(manifest["steps"][service])
                logger.info(service, "publication_already_done", {"ledger_key": ledger_key})
                continue
            manifest["steps"][service] = {"status": RUNNING}
            result = adapter.publish(context)
            payload = result.public()
            payload["ledger_key"] = ledger_key
            if result.reason:
                payload["reason"] = result.reason
            manifest["steps"][service] = payload
            manifest["publications"][service] = payload
            state["published_any"] = True
            if result.status in (pub.PUBLISHED, pub.DUPLICATE):
                store.ledger_put(ledger_key, {
                    "status": pub.PUBLISHED,
                    "run_id": manifest["run_id"],
                    "external_ids": result.external_ids,
                    "recorded_at": utc_timestamp(),
                })
            else:
                state["publication_failed"] = True
                state["publication_deferred"] = state["publication_deferred"] or result.status == pub.PENDING
                if result.required:
                    state["required_failure"] = True
                if result.status in (pub.PENDING, pub.FAILED):
                    store.enqueue_pending({
                        "reason": result.reason,
                        "status": result.status,
                        "services": [service],
                        "artifacts": sorted(context.artifacts),
                    })
        manifest["publications"]["_state"] = {
            "published_any": state["published_any"],
            "failed": state["publication_failed"],
            "deferred": state["publication_deferred"],
            "required_failed": state["required_failure"],
        }

    def _inventory_ids(self, store, manifest):
        service = manifest["service"]
        ids = {"dependency_track": {}, "defectdojo": {}}
        # The record that existed before this run: a run never compares against itself.
        record = getattr(self, "_prior_inventory", None)
        if record:
            ids["dependency_track"].update({
                "release_sbom_sha256": record.get("sbom_sha256"),
                "release_component_fingerprint": record.get("component_fingerprint"),
            })
        if store.artifact_path("sbom.cdx.json").is_file():
            ids["dependency_track"]["sbom_sha256"] = store.sha256("sbom.cdx.json")
        dojo = store.ledger_get(f"defectdojo:{service}:test")
        if dojo and dojo.get("external_ids", {}).get("test"):
            ids["defectdojo"]["test"] = dojo["external_ids"]["test"]
        return ids

    def _ledger_key(self, service, context):
        digest = "-"
        if service == "dependency_track" and context.sbom_path:
            digest = _sha256(context.sbom_path)
        elif context.report_path:
            digest = _sha256(context.report_path)
        identity = [service, context.service, context.publish_target or context.event,
                    str(context.version or ""), digest[:16]]
        return ":".join(identity)

    # -- finishing ---------------------------------------------------------
    def _finish(self, store, manifest, logger, state, artifacts, started):
        manifest["timestamps"]["finished_at"] = utc_timestamp()
        scan_ok = manifest["security"].get("scan_successful", False)
        attempted = state["published_any"]
        publication_ok = None
        if attempted:
            publication_ok = not state["publication_failed"]
        if not scan_ok:
            status = "failed"
        elif state["required_failure"]:
            status = "partial"
        elif state["publication_failed"]:
            status = "partial"
        else:
            status = "completed"
        manifest["result"] = {
            "status": status,
            "scan_successful": scan_ok,
            "findings_detected": manifest["security"].get("findings_detected", False),
            "publication_successful": publication_ok,
            "required_publication_failed": state["required_failure"],
            "technical_failure": state["technical_failure"],
        }
        if self.config.get("artifacts.create_manifest", True):
            manifest["artifacts"] = {
                name: {"sha256": store.sha256(name),
                       "size_bytes": store.artifact_path(name).stat().st_size}
                for name in self._evidentiary_files(store)
            }
        store.write_json("publication.json", {
            "run_id": manifest["run_id"],
            "publications": {name: value for name, value in manifest["publications"].items()
                             if name != "_state"},
            "state": manifest["publications"].get("_state", {}),
        })
        if self.config.get("artifacts.create_manifest", True):
            store.write_json("manifest.json", manifest)
        logger.info("run", "workflow_finished", {
            "status": status,
            "scan_successful": scan_ok,
            "publication_successful": publication_ok,
            "problems": len(manifest["problems"]),
        })
        state["status"] = status
        return status

    def _evidentiary_files(self, store):
        names = ["manifest.json", "decisions.json", "trivy-report.json",
                 "trivy-report.sanitized.json", "sbom.cdx.json", "publication.json",
                 "execution.log"]
        return [name for name in names if store.artifact_path(name).is_file()]

    def _discard_reports(self, store, logger, state):
        if store.pending_entries():
            logger.warning("evidence", "reports_kept_for_pending_publication", {})
            store.write_checksums(self._evidentiary_files(store))
            return
        for name in ("trivy-report.json", "trivy-report.sanitized.json", "sbom.cdx.json"):
            store.artifact_path(name).unlink(missing_ok=True)
        store.write_checksums(self._evidentiary_files(store))
        logger.info("evidence", "reports_discarded", {"reason": "artifacts.preserve_reports is false"})

    def _exit_code(self, state):
        if state["technical_failure"] and self.config.get("execution.fail_on_scanner_error", True):
            return 1
        if state["required_failure"]:
            return 1
        if self.config.get("execution.fail_on_findings", False) and state["findings"]:
            return 3
        return 0

    def _environment(self):
        return {
            "runner": self.source,
            "ci": self.source in ("github", "act"),
            "python": platform.python_version(),
            "platform": platform.system(),
            "repository_root": str(self.config.repo_root),
            "trivy_runner": self.config.get("trivy.runner"),
            "trivy_image": self.config.get("trivy.image") if self.config.get("trivy.runner") == "docker" else None,
            "artifact_directory": self.config.get("artifacts.directory"),
        }

    def _config_name(self):
        source = self.config.source
        if not source:
            return None
        try:
            return str(Path(source).resolve().relative_to(self.config.repo_root))
        except ValueError:
            return Path(source).name

    def _redactor(self):
        values = []
        for block in ("barad_dur", "dependency_track", "defectdojo"):
            for key in SECRET_ENV_KEYS:
                name = self.config.get(f"integrations.{block}.{key}")
                if name:
                    values.append(self.environ.get(name) or "")
        return Redactor(values)


def _empty_report():
    from .changes import ChangeReport
    report = ChangeReport()
    report.problems.append({"code": "no_git_context"})
    return report


def _sha256(path):
    import hashlib
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 256), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _component_fingerprint(path):
    """Stable digest of the PURL set, used to classify release inventory changes."""
    import hashlib
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    purls = sorted(component.get("purl") for component in document.get("components") or []
                   if isinstance(component, dict) and component.get("purl"))
    return hashlib.sha256("\n".join(purls).encode("utf-8")).hexdigest()


def _repository_name(context, config):
    try:
        result = subprocess.run(
            ["git", "-C", str(config.repo_root), "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=30)
        if result.returncode == 0 and result.stdout.strip():
            name = result.stdout.strip().rstrip("/")
            return re.sub(r"\.git$", "", name.split("/")[-1].split(":")[-1])
    except (OSError, subprocess.SubprocessError):
        pass
    return Path(config.repo_root).name

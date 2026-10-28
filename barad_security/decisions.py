"""Decision engine: always Trivy, conditional SBOM, explicit publication plan.

Every decision carries a machine-readable reason so the manifest explains why a
step ran or was skipped, even when it was skipped because of an unavailable
integration or a missing base reference.
"""

# Deterministic priority: the first triggered reason is reported as `sbom_reason`.
REASON_PRIORITY = (
    "base_reference_unavailable",
    "release_event",
    "dependency_changed",
    "application_version_changed",
    "build_context_changed",
    "initial_inventory_missing",
)


def _generate_on(config):
    return config.get("sbom.generate_on", {}) or {}


def evaluate(config, context, report, version_info=None, *, inventory_present=False):
    """Return the decision document for this run."""
    generate_on = _generate_on(config)
    release_event = context.event == "release"
    triggers = {
        "dependency_changed": bool(report.dependency_changed and generate_on.get("dependency_changes", True)),
        "application_version_changed": bool(report.version_changed and generate_on.get("version_changes", True)),
        "build_context_changed": bool(report.build_context_changed and generate_on.get("build_changes", True)),
        "release_event": bool(release_event and generate_on.get("release", True)),
        "initial_inventory_missing": not inventory_present,
        "base_reference_unavailable": not report.base_available,
    }
    disabled = {}
    if report.dependency_changed and not triggers["dependency_changed"]:
        disabled["dependency_changed"] = "sbom.generate_on.dependency_changes is false"
    if report.version_changed and not triggers["application_version_changed"]:
        disabled["application_version_changed"] = "sbom.generate_on.version_changes is false"
    if report.build_context_changed and not triggers["build_context_changed"]:
        disabled["build_context_changed"] = "sbom.generate_on.build_changes is false"
    if release_event and not triggers["release_event"]:
        disabled["release_event"] = "sbom.generate_on.release is false"

    reasons = []
    if not config.get("sbom.enabled", True):
        sbom_enabled = False
        reasons.append({"code": "sbom_disabled", "detail": "sbom.enabled is false"})
    else:
        sbom_enabled = True

    matched = [code for code in REASON_PRIORITY if triggers.get(code)]
    if config.get("sbom.enabled", True) and not matched:
        reasons.append({"code": "no_inventory_change",
                        "detail": "no dependency, version, build-context or release trigger"})
    for code in matched:
        detail = {
            "base_reference_unavailable": "no trustworthy base commit; generating conservatively",
            "release_event": "release event",
            "dependency_changed": "dependency inventory changed: " + ", ".join(report.files_changed[:5]),
            "application_version_changed": f"{report.previous_version} -> {report.current_version}",
            "build_context_changed": "build context changed: " + ", ".join(report.files_changed[:5]),
            "initial_inventory_missing": "no previous reusable inventory for this service/version",
        }[code]
        reasons.append({"code": code, "detail": detail})
    for code, detail in disabled.items():
        reasons.append({"code": f"{code}_suppressed", "detail": detail})
    for problem in report.problems:
        reasons.append({"code": "change_detection_problem", "detail": problem})

    generate_sbom = bool(sbom_enabled and matched)
    if not sbom_enabled:
        sbom_reason = "sbom_disabled"
    else:
        sbom_reason = matched[0] if matched else "no_inventory_change"

    decisions = Decisions(
        run_trivy=True,
        generate_sbom=generate_sbom,
        sbom_reason=sbom_reason,
        triggers=triggers,
        reasons=reasons,
        version=version_info.public() if version_info else None,
    )
    decisions.publications = plan_publications(config, context, decisions)
    return decisions


class Decisions:
    def __init__(self, *, run_trivy, generate_sbom, sbom_reason, triggers, reasons, version=None,
                 publications=None):
        self.run_trivy = run_trivy
        self.generate_sbom = generate_sbom
        self.sbom_reason = sbom_reason
        self.triggers = triggers
        self.reasons = reasons
        self.version = version
        self.publications = publications or {}

    def public(self):
        return {
            "run_trivy": self.run_trivy,
            "generate_sbom": self.generate_sbom,
            "sbom_reason": self.sbom_reason,
            "triggers": dict(self.triggers),
            "publications": {step: dict(plan) for step, plan in self.publications.items()},
            "reasons": list(self.reasons),
            "application_version": self.version,
        }


def plan_publications(config, context, decisions):
    """Decide, per integration, whether this run publishes, and why."""
    plan = {}
    release_event = context.event == "release"
    pull_request_event = context.event == "pr"

    barad = config.get("integrations.barad_dur", {}) or {}
    if barad.get("enabled"):
        plan["barad_dur"] = {"action": "publish", "reason": "integration_enabled",
                             "required": bool(barad.get("required"))}
    else:
        plan["barad_dur"] = {"action": "skip", "reason": "integration_disabled", "required": False}

    dt = config.get("integrations.dependency_track", {}) or {}
    if not dt.get("enabled"):
        plan["dependency_track"] = {"action": "skip", "reason": "integration_disabled", "required": False}
    elif pull_request_event:
        # Temporary inventory: evidence only, never a permanent project.
        plan["dependency_track"] = {"action": "skip", "reason": "pull_request_is_temporary",
                                    "required": bool(dt.get("required"))}
    elif release_event and dt.get("publish_on_release", True) and decisions.generate_sbom:
        plan["dependency_track"] = {"action": "publish", "reason": "release_event",
                                    "target": "release", "required": bool(dt.get("required"))}
    elif (not release_event and dt.get("update_development_project") and decisions.generate_sbom):
        plan["dependency_track"] = {"action": "publish", "reason": "development_inventory_update",
                                    "target": "development", "required": bool(dt.get("required"))}
    else:
        plan["dependency_track"] = {"action": "skip", "reason": "not_a_release", "required": bool(dt.get("required"))}

    dojo = config.get("integrations.defectdojo", {}) or {}
    if not dojo.get("enabled") or not dojo.get("publish_trivy_reports"):
        plan["defectdojo"] = {"action": "skip", "reason": "integration_disabled", "required": bool(dojo.get("required"))}
    elif pull_request_event and not dojo.get("publish_on_pull_request"):
        plan["defectdojo"] = {"action": "skip", "reason": "pull_request_import_disabled",
                              "required": bool(dojo.get("required"))}
    else:
        plan["defectdojo"] = {"action": "publish", "reason": "evidence_import_enabled",
                              "required": bool(dojo.get("required"))}
    return plan

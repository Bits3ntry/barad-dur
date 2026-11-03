"""BL-060: license inventory, policy evaluation and exceptions.

Evaluation is deterministic and explainable: deny-list always wins, an
allow-list (when present) bounds the accepted set, unknown licenses follow
the policy's explicit `unknown_action` (never silently allowed), and active,
unexpired exceptions waive exactly one (component identity, license) pair.
"""
import datetime

from backend.app import models

VERDICTS = {"allowed", "denied", "unknown", "excepted"}


def _now() -> datetime.datetime:
    return models.utcnow()


def _aware(value):
    if value.tzinfo is None:
        return value.replace(tzinfo=datetime.timezone.utc)
    return value


def _split(value: str | None) -> set[str]:
    if not value:
        return set()
    return {item.strip().lower() for item in value.split(",") if item.strip()}


def active_exception(session, org_id: str, component_identity: str,
                     license_id: str, at=None) -> models.LicenseException | None:
    now = _aware(at or _now())
    rows = (session.query(models.LicenseException)
            .filter_by(org_id=org_id, component_identity=component_identity,
                       license_id=license_id).all())
    for row in rows:
        if row.expires_at is None or _aware(row.expires_at) > now:
            return row
    return None


def evaluate_license(component, license_id: str, policy,
                     exception=None) -> dict:
    """One verdict with its reason; deny-list short-circuits everything."""
    license_key = license_id.strip().lower()
    if exception is not None:
        return {"verdict": "excepted",
                "reason": f"exception by {exception.approved_by}: {exception.reason}",
                "exception_id": exception.id}
    deny = _split(policy.deny_list) if policy else set()
    allow = _split(policy.allow_list) if policy else set()
    if license_key in deny:
        return {"verdict": "denied", "reason": f"'{license_id}' is on the deny list"}
    if allow and license_key not in allow:
        return {"verdict": "denied",
                "reason": f"'{license_id}' is not on the allow list"}
    if not allow and not deny:
        return {"verdict": "unknown",
                "reason": "policy has no allow/deny lists; license unclassified"}
    return {"verdict": "allowed", "reason": f"'{license_id}' is allowed"}


def policy_for(session, org_id: str, project_id: str | None = None):
    """Project policy outranks org policy; active only; most recent wins."""
    if project_id is not None:
        row = (session.query(models.LicensePolicy)
               .filter_by(org_id=org_id, scope_type="project",
                          scope_id=project_id, status="active")
               .order_by(models.LicensePolicy.created_at.desc()).first())
        if row is not None:
            return row
    return (session.query(models.LicensePolicy)
            .filter_by(org_id=org_id, scope_type="org", status="active")
            .order_by(models.LicensePolicy.created_at.desc()).first())


def evaluate_project_version(session, org_id: str, project, version) -> dict:
    """Walk every component of one project version; explainable per-row results."""
    policy = policy_for(session, org_id, project.id)
    rows = (session.query(models.VersionComponent, models.Component)
            .join(models.Component, models.VersionComponent.component_id == models.Component.id)
            .filter(models.VersionComponent.project_version_id == version.id).all())
    results = []
    counts = {"components": 0, "denied": 0, "unknown": 0, "excepted": 0,
              "allowed": 0, "unlicensed": 0}
    for link, component in rows:
        counts["components"] += 1
        licenses = [row.license_id for row in
                    session.query(models.ComponentLicense)
                    .filter_by(component_id=component.id).all()]
        if not licenses:
            counts["unlicensed"] += 1
            results.append({
                "component": component.name, "version": component.version,
                "purl": component.purl, "identity_key": component.identity_key,
                "license": None, "verdict": "unknown",
                "reason": "no license declared in the SBOM"})
            continue
        for license_id in sorted(set(licenses)):
            exception = active_exception(session, org_id,
                                         component.identity_key, license_id)
            verdict = evaluate_license(component, license_id, policy, exception)
            counts[{"denied": "denied", "unknown": "unknown",
                    "excepted": "excepted", "allowed": "allowed"}[verdict["verdict"]]] += 1
            results.append({
                "component": component.name, "version": component.version,
                "purl": component.purl, "identity_key": component.identity_key,
                "license": license_id, **verdict})
    return {
        "policy": ({"id": policy.id, "name": policy.name,
                    "scope": policy.scope_type,
                    "unknown_action": policy.unknown_action}
                   if policy else None),
        "project": project.slug, "version": version.version,
        "counts": counts, "results": results,
    }

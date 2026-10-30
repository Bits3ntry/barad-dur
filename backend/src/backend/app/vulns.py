"""OSV.dev-backed vulnerability engine (F1).

Queries the OSV v1 API for each inventoried component, upserts the global
advisory catalog and creates deduped findings. The OSV client uses the
stdlib `urllib` (no new runtime dependency) with a hard timeout; tests stub
`fetch_batch`. Page-limit limitation: when OSV answers with a
`next_page_token` the remaining pages are not fetched in the POC and the
result is reported as truncated rather than silently incomplete — the gate
fixture has single-digit advisories, and the full pagination loop is deferred
until a real inventory needs it.
"""
import datetime
import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urlparse

from backend.app import models

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_DETAIL_URL = "https://api.osv.dev/v1/vulns"

# purl type -> OSV ecosystem. Unmapped ecosystems are skipped (reported), not
# guessed: a wrong mapping creates wrong findings silently, which is worse
# than a smaller honest inventory.
PURL_TYPES = {
    "pypi": "PyPI",
    "npm": "npm",
    "golang": "Go",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "maven": "Maven",
    "nuget": "NuGet",
    "composer": "Packagist",
}


def parse_purl(purl: str) -> dict | None:
    """Minimal purl parsing: {'ecosystem', 'name'} or None when unqueryable."""
    try:
        rest = purl.split("pkg:", 1)[1]
    except (IndexError, AttributeError):
        return None
    ptype, _, remainder = rest.partition("/")
    ecosystem = PURL_TYPES.get(ptype.lower())
    if not ecosystem or not remainder:
        return None
    name = remainder.partition("@")[0]
    name = urllib.parse.unquote(name)
    if ecosystem == "PyPI":
        name = name.lower().replace("_", "-").replace(".", "-")
    if not name:
        return None
    return {"ecosystem": ecosystem, "name": name}


def vulnerability_fingerprint(org_id: str, project_id: str, identity_key: str,
                              source_id: str) -> str:
    """Per-kind recipe: one finding per (org, project, component, advisory)."""
    base = f"v1|vulnerability|{org_id}|{project_id}|{identity_key}|{source_id}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


def severity_of(vuln: dict) -> tuple[str | None, str | None]:
    """(severity label, cvss vector) from an OSV advisory, or (None, None)."""
    database_specific = vuln.get("database_specific") or {}
    label = database_specific.get("severity")
    vector = None
    for entry in vuln.get("severity") or []:
        if isinstance(entry, dict) and entry.get("type", "").startswith("CVSS"):
            vector = entry.get("score")
            break
    return (label.upper() if isinstance(label, str) and label else None, vector)


def parse_timestamp(value) -> datetime.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def same_timestamp(left: datetime.datetime | None,
                   right: datetime.datetime | None) -> bool:
    """Tz-safe equality: backends may drop tzinfo (sqlite) or keep it (postgres)."""
    if left is None or right is None:
        return left == right

    def _utc_naive(value: datetime.datetime) -> datetime.datetime:
        if value.tzinfo is None:
            return value
        return value.astimezone(datetime.timezone.utc).replace(tzinfo=None)

    return _utc_naive(left) == _utc_naive(right)


def fetch_detail(source_id: str, *, timeout_seconds: float = 15.0) -> dict | None:
    """GET the full advisory record; None when OSV answers without JSON."""
    request = urllib.request.Request(f"{OSV_DETAIL_URL}/{source_id}", method="GET")
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        payload = json.loads(response.read().decode("utf-8"))
    return payload if isinstance(payload, dict) else None


def fetch_batch(queries: list[dict], *, timeout_seconds: float = 15.0) -> list:
    """POST to querybatch, return the `results` list (same order as queries)."""
    request = urllib.request.Request(
        OSV_BATCH_URL,
        data=json.dumps({"queries": queries}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        payload = json.loads(response.read().decode("utf-8"))
    results = payload.get("results") if isinstance(payload, dict) else None
    return results if isinstance(results, list) else []


def analyze(session, org_id: str, project: models.Project,
            project_version: models.ProjectVersion,
            *, fetch=None, fetch_one=None) -> dict:
    """Match the version's inventory against OSV; upsert advisories + findings.

    Idempotent on the finding fingerprint: reruns refresh `last_seen_at`
    instead of duplicating. OSV's querybatch answers `{id, modified}` lists
    only, so advisory details are fetched per id, short-circuited when the
    catalog already holds that advisory with the same `modified` timestamp.

    Returns counters, truncated flag included.
    """
    fetch = fetch or fetch_batch
    fetch_one = fetch_one or fetch_detail
    links = (session.query(models.VersionComponent, models.Component)
             .join(models.Component,
                   models.VersionComponent.component_id == models.Component.id)
             .filter(models.VersionComponent.project_version_id == project_version.id)
             .all())

    queries, rows = [], []
    for _link, component in links:
        if not component.purl:
            continue
        parsed = parse_purl(component.purl)
        if parsed is None:
            continue
        queries.append({"package": parsed, "version": component.version or ""})
        rows.append((component, parsed))

    counters = {"components_queried": len(rows), "components_skipped_unmapped": len(links) - len(rows),
                "advisories_found": 0, "findings_created": 0, "findings_refreshed": 0,
                "details_fetched": 0, "truncated": False}
    if not queries:
        return counters

    try:
        results = fetch(queries)
    except (urllib.error.URLError, OSError, ValueError, TimeoutError) as error:
        counters["error"] = f"osv request failed: {error}"
        return counters

    now = models.utcnow()
    for (component, _parsed), result in zip(rows, results):
        if not isinstance(result, dict):
            continue
        if isinstance(result.get("next_page_token"), str) and result["next_page_token"]:
            counters["truncated"] = True
        for stub in result.get("vulns") or []:
            if not isinstance(stub, dict) or not isinstance(stub.get("id"), str):
                continue
            counters["advisories_found"] += 1
            advisory = session.query(models.Vulnerability).filter_by(
                source_id=stub["id"]).one_or_none()
            modified = parse_timestamp(stub.get("modified"))
            if advisory is None or not same_timestamp(advisory.modified, modified):
                try:
                    detail = fetch_one(stub["id"])
                except (urllib.error.URLError, OSError, ValueError, TimeoutError) as error:
                    counters.setdefault("detail_errors", []).append(
                        {"id": stub["id"], "reason": f"osv detail failed: {error}"})
                    continue
                if detail is None:
                    counters.setdefault("detail_errors", []).append(
                        {"id": stub["id"], "reason": "osv detail missing"})
                    continue
                counters["details_fetched"] += 1
                advisory = _upsert_advisory(session, detail)
            fingerprint = vulnerability_fingerprint(
                org_id, project.id, component.identity_key, advisory.source_id)
            finding = (session.query(models.Finding)
                       .filter_by(org_id=org_id, fingerprint=fingerprint)
                       .one_or_none())
            if finding is None:
                session.add(models.Finding(
                    org_id=org_id, project_id=project.id, kind="vulnerability",
                    fingerprint=fingerprint, source="osv",
                    title=advisory.title, severity=advisory.severity,
                    url=advisory.url,
                    detail=f"OSV advisory {advisory.source_id}; alias {advisory.cve_id}"
                           if advisory.cve_id else None,
                    component_id=component.id,
                    vulnerability_id=advisory.id,
                    last_seen_version_id=project_version.id,
                    first_seen_at=now, last_seen_at=now,
                    updated_at=now,))
                counters["findings_created"] += 1
            else:
                finding.last_seen_at = now
                finding.last_seen_version_id = project_version.id
                finding.severity = advisory.severity
                finding.title = advisory.title
                finding.updated_at = now
                counters["findings_refreshed"] += 1
    return counters


def _upsert_advisory(session, vuln: dict) -> models.Vulnerability:
    severity, vector = severity_of(vuln)
    cve = next((a for a in (vuln.get("aliases") or [])
                if isinstance(a, str) and a.startswith("CVE-")), None)
    references = vuln.get("references") or []
    url = next((r.get("url") for r in references
                if isinstance(r, dict) and isinstance(r.get("url"), str)), None)
    advisory = session.query(models.Vulnerability).filter_by(
        source_id=vuln["id"]).one_or_none()
    if advisory is None:
        advisory = models.Vulnerability(source_id=vuln["id"], cve_id=cve,
                                        title=vuln.get("summary"),
                                        severity=severity, cvss_vector=vector,
                                        url=url,
                                        published=parse_timestamp(vuln.get("published")),
                                        modified=parse_timestamp(vuln.get("modified")),
                                        fetched_at=models.utcnow())
        session.add(advisory)
        session.flush()
    return advisory


def resolve_version(session, org_id: str, project: str, version: str):
    from backend.app.routers.inventory import _resolve_version

    return _resolve_version(session, org_id, project, version)


def is_osv_url(url: str) -> bool:
    """Guard for tests/stubs: the client must only ever talk to api.osv.dev."""
    parsed = urlparse(OSV_BATCH_URL)
    return url.startswith(f"https://{parsed.hostname}/")

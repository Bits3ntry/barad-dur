"""Vulnerabilities: one row per PROBLEM, with every finding behind it.

The console needs two readings of the same data, and conflating them is what
makes security panels unusable:

* **Findings** — occurrences. The same SQL injection in two endpoints is two
  findings, because the fix is two changes in two files.
* **Vulnerabilities** — the problem itself. One row, with how many places it
  appears in, who is exposed, whether an exploit exists and what the fix is.
  This is the row you triage, ticket and close.

Grouping is by *signature*, not by row: a rule id for SAST and configuration
findings, a CVE id for dependency advisories. A secret groups by rule too — five
leaked keys in five files are one policy problem with five places to rotate.

Exposure is reported as inputs, never as a verdict without its evidence: CVSS
and severity come from the artifact, KEV/EPSS from the enrichment tables when a
feed has been imported, reachability from whether the affected project has
assets attached. When something is unknown the API says `known: false` with the
reason, because a blank reads like zero.
"""
import hashlib
import json

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, cvss, models, projects as projects_ref, severity as severity_vocab
from backend.app.ancestry import ancestry, links_of
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1", tags=["vulnerabilities"])

OPEN_STATUSES = {"open", "acknowledged"}
from backend.app.status import CLOSED_STATUSES
PRIORITY_ORDER = ["P0", "P1", "P2", "P3", "P4", None]

VECTOR_LABELS = {
    "dependency-cve": "Dependency CVE",
    "credential": "Exposed credential",
    "sast": "Code weakness",
    "misconfig": "Insecure configuration",
}

# A secret is closed by rotating it, not by committing: this drives what the
# console tells the operator to do.
REMEDIATION = {
    "dependency-cve": "Upgrade the package",
    "credential": "Rotate the credential",
    "sast": "Change the code",
    "misconfig": "Change the configuration",
}


def _worst_severity(values) -> str:
    best = "UNKNOWN"
    for value in values:
        if value and severity_vocab.rank(value) < severity_vocab.rank(best):
            best = severity_vocab.canonical(value)
    return best


def _worst_priority(values) -> str | None:
    known = [value for value in values if value in PRIORITY_ORDER]
    if not known:
        return None
    return min(known, key=PRIORITY_ORDER.index)


def _asset_ids_for_project(session: Session, org_id: str, project_id: str) -> set[str]:
    """Assets attached to a project, directly or through a typed link."""
    direct = {row.id for row in session.query(models.Asset)
              .filter_by(org_id=org_id, project_id=project_id).all()}
    linked = {row.asset_id for row in session.query(models.AssetLink)
              .filter_by(org_id=org_id, entity_type="project", entity_id=project_id)
              .filter(models.AssetLink.removed_at.is_(None)).all()}
    return direct | linked


def _detail_of(finding: models.Finding) -> dict:
    """The per-finding evidence blob written by the ingest, when it is JSON."""
    if not finding.detail or not finding.detail.strip().startswith("{"):
        return {}
    try:
        parsed = json.loads(finding.detail)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _enrichment(session: Session, cve_id: str | None) -> dict:
    if not cve_id:
        return {"kev": {"known": False, "listed": False, "reason": "no advisory id"},
                "epss": {"known": False, "score": None, "reason": "no advisory id"},
                "exploit": {"known": False, "available": None,
                            "reason": "not a CVE: no exploit feed applies"}}
    kev = session.get(models.KevEntry, cve_id)
    epss = session.get(models.EpssScore, cve_id)
    return {
        "kev": {"known": kev is not None, "listed": kev is not None,
                "date_added": kev.date_added if kev else None,
                "due_date": kev.due_date if kev else None,
                "source": kev.source if kev else None,
                "fetched_at": kev.fetched_at.isoformat() if kev else None},
        "epss": {"known": epss is not None,
                 "score": epss.epss if epss else None,
                 "percentile": epss.percentile if epss else None,
                 "source": "first.org/epss" if epss else None,
                 "fetched_at": epss.fetched_at.isoformat() if epss else None},
        "exploit": {"known": kev is not None,
                    "available": True if kev is not None else None,
                    "reason": ("listed in CISA KEV" if kev is not None
                               else "no exploit feed connected")},
    }


def _signature_of(session: Session, finding: models.Finding) -> tuple[str, str | None, dict]:
    """(signature, cve_id, advisory) — what makes two findings the same problem."""
    if finding.vulnerability_id:
        advisory = session.get(models.Vulnerability, finding.vulnerability_id)
        if advisory is not None:
            cve_id = advisory.cve_id or advisory.source_id
            return cve_id, cve_id, {"title": advisory.title,
                                    "cvss_vector": advisory.cvss_vector,
                                    "url": advisory.url}
    return (finding.rule_id or finding.title or "unnamed"), None, {}


def _risk_of(severity: str, enrichment: dict, reachable: bool) -> dict:
    """One verdict with its reasons, never a number without an explanation.

    Deliberately simple and auditable: known-exploited beats everything, then
    severity, then whether anything outside can actually reach it.
    """
    reasons: list[str] = []
    if enrichment["kev"]["listed"]:
        reasons.append("known exploited (KEV)")
    if severity in {"CRITICAL", "HIGH"}:
        reasons.append(f"severity {severity}")
    if reachable:
        reasons.append("reachable from an inventoried asset")
    else:
        reasons.append("no asset is attached to the affected project")
    if enrichment["kev"]["listed"] or severity == "CRITICAL":
        label = "critical"
    elif severity == "HIGH" and reachable:
        label = "high"
    elif severity in {"HIGH", "MEDIUM"}:
        label = "medium"
    else:
        label = "low"
    return {"label": label, "reasons": reasons}


def _groups(session: Session, org: models.Organization,
            include_suppressed: bool, by: str = "component") -> list[dict]:
    """One row per problem at the granularity the caller asks for.

    `by="component"` (the default) is the acting view: a CVE against two packages
    is two rows there, because it is two upgrades and two status decisions.
    `by="signature"` is the reading view: a vulnerability is one thing however
    many subjects carry it, which is what the estate list prints and what its
    columns promise. Both are the same findings, bucketed differently — nothing
    downstream re-derives the counts.
    """
    query = session.query(models.Finding).filter(models.Finding.org_id == org.id)
    if not include_suppressed:
        query = query.filter(models.Finding.status != "suppressed")
    findings = query.all()

    assets_by_project: dict[str, set[str]] = {}
    projects_cache: dict[str, models.Project] = {}
    components_cache: dict[str, models.Component] = {}
    buckets: dict[str, dict] = {}

    for finding in findings:
        signature, cve_id, advisory = _signature_of(session, finding)
        vector = finding.vector or ("dependency-cve" if cve_id else "sast")
        component = None
        if finding.component_id:
            component = components_cache.get(finding.component_id)
            if component is None:
                component = session.get(models.Component, finding.component_id)
                if component is not None:
                    components_cache[component.id] = component
        # A CVE against two different packages is two problems when you act, and
        # one vulnerability when you read: the component belongs in the key only
        # for the acting view.
        component_key = ""
        if by == "component" and cve_id and component is not None:
            component_key = component.name or component.purl or component.identity_key
        key = f"{vector}|{signature}|{component_key}"
        bucket = buckets.get(key)
        if bucket is None:
            bucket = buckets[key] = {
                "key": key, "vector": vector, "signature": signature,
                "cve_id": cve_id, "advisory": advisory, "findings": [],
                "components": {}, "projects": {}, "versions": {}, "titles": set(),
            }
        if finding.title:
            bucket["titles"].add(finding.title)
        bucket["findings"].append(finding)
        if component is not None:
            bucket["components"][component.id] = {
                "id": component.id, "name": component.name,
                "version": component.version, "purl": component.purl,
                "license": component.license,
                "manifest_path": component.manifest_path}
        if finding.project_id not in assets_by_project:
            assets_by_project[finding.project_id] = _asset_ids_for_project(
                session, org.id, finding.project_id)
        project = projects_cache.get(finding.project_id)
        if project is None:
            project = session.get(models.Project, finding.project_id)
            if project is not None:
                projects_cache[project.id] = project
        if project is not None:
            bucket["projects"][project.id] = {
                "id": project.id, "slug": project.slug, "name": project.name,
                "assets": len(assets_by_project[finding.project_id])}
            version = (session.get(models.ProjectVersion, finding.last_seen_version_id)
                       if finding.last_seen_version_id else None)
            if version is not None:
                bucket["versions"].setdefault(
                    (project.slug, version.component_id, version.version), []).append(finding)

    rows = []
    for bucket in buckets.values():
        findings = bucket["findings"]
        vector = bucket["vector"]
        asset_ids: set[str] = set()
        for finding in findings:
            asset_ids |= assets_by_project.get(finding.project_id, set())
        assets = [session.get(models.Asset, asset_id) for asset_id in sorted(asset_ids)]
        assets = [asset for asset in assets if asset is not None]

        details = [_detail_of(finding) for finding in findings]
        cvss_scores: list[float] = [float(d["cvss_score"]) for d in details
                                    if isinstance(d.get("cvss_score"), (int, float))]
        # Not every producer stores a number: the runtime ingest keeps only the
        # vector. The base score is derivable from it, so a scanner that forgot
        # the number no longer reads as "unscored" — and the row says which of the
        # two it is, because a computed score is not a quoted one.
        advisory_vector = bucket["advisory"].get("cvss_vector")
        derived = False
        if cvss_scores:
            cvss_score = max(cvss_scores)
        else:
            cvss_score = cvss.base_score(advisory_vector)
            derived = cvss_score is not None
        fixed = sorted({d["fixed_version"] for d in details
                        if isinstance(d.get("fixed_version"), str)})
        severity = _worst_severity([finding.severity for finding in findings])
        enrichment = _enrichment(session, bucket["cve_id"])
        reachable = bool(assets)
        first_seen = min((f.first_seen_at for f in findings if f.first_seen_at), default=None)
        last_seen = max((f.last_seen_at for f in findings if f.last_seen_at), default=None)
        versions = [
            {"project": project_slug, "component_id": component_id,
             "version": version_label, "findings": len(version_findings),
             "open_findings": sum(1 for f in version_findings if f.status in OPEN_STATUSES),
             "severity": _worst_severity([f.severity for f in version_findings])}
            for (project_slug, component_id, version_label),
            version_findings in bucket["versions"].items()
        ]
        versions.sort(key=lambda row: (row["project"], row["version"]))

        locations = []
        for finding in sorted(findings, key=lambda f: (severity_vocab.rank(f.severity),
                                                       f.path or "")):
            project = projects_cache.get(finding.project_id)
            component = (components_cache.get(finding.component_id)
                         if finding.component_id else None)
            locations.append({
                "finding_id": finding.id,
                "project": project.slug if project else None,
                "path": finding.path, "line": finding.line,
                "component": component.name if component else None,
                "component_version": component.version if component else None,
                "tool": finding.tool, "status": finding.status,
                "severity": finding.severity, "assignee": finding.assignee,
                "first_seen_at": (finding.first_seen_at.isoformat()
                                  if finding.first_seen_at else None),
                "last_seen_at": (finding.last_seen_at.isoformat()
                                 if finding.last_seen_at else None),
            })

        rows.append({
            "id": hashlib.sha1(bucket["key"].encode("utf-8")).hexdigest()[:16],
            "key": bucket["key"],
            "vector": vector,
            "vector_label": VECTOR_LABELS.get(vector, vector),
            "kind": findings[0].kind,
            "signature": bucket["signature"],
            "cve_id": bucket["cve_id"],
            "title": (bucket["advisory"].get("title")
                      or (sorted(bucket["titles"])[0] if bucket["titles"]
                          else bucket["signature"])),
            "severity": severity,
            "priority": _worst_priority([finding.priority for finding in findings]),
            "cvss": {"known": cvss_score is not None,
                     "score": cvss_score,
                     "vector": advisory_vector,
                     "derived": derived,
                     "reason": None if cvss_score is not None
                     else "the scanner stated neither a score nor a v3 vector"},
            "fix": {"available": bool(fixed), "versions": fixed,
                    "reason": None if fixed else "no fixed version stated by the scanner"},
            "remediation": REMEDIATION.get(vector),
            "enrichment": enrichment,
            "exposure": _risk_of(severity, enrichment, reachable),
            "reachable": reachable,
            "findings": len(findings),
            "open_findings": sum(1 for f in findings if f.status in OPEN_STATUSES),
            "statuses": sorted({f.status for f in findings}),
            "components": sorted(bucket["components"].values(),
                                 key=lambda row: (row["name"] or "", row["version"] or "")),
            "projects": sorted(bucket["projects"].values(), key=lambda row: row["slug"]),
            "versions": versions,
            "assets": {"count": len(assets),
                       "sample": [{"id": asset.id, "type": asset.type,
                                   "value": asset.value} for asset in assets[:8]],
                       "coverage": ("complete" if assets else
                                    "no asset is attached to the affected projects")},
            "locations": locations,
            "first_seen_at": first_seen.isoformat() if first_seen else None,
            "last_seen_at": last_seen.isoformat() if last_seen else None,
            "assignee": next((f.assignee for f in findings if f.assignee), None),
            "url": bucket["advisory"].get("url"),
        })

    rows.sort(key=lambda row: (severity_vocab.rank(row["severity"]),
                               -int(row["enrichment"]["kev"]["listed"]),
                               -row["findings"], row["signature"]))
    return rows


def _match(rows: list[dict], ref: str) -> dict | None:
    lowered = ref.lower()
    return next((item for item in rows
                 if item["id"] == ref
                 or (item["cve_id"] or "").lower() == lowered
                 or item["signature"].lower() == lowered), None)


# ───────────────────────────── one advisory, whole estate ─────────────────────
#
# `_groups` splits by (vector, signature, component) on purpose: one CVE against
# two packages is two rows in the list, because the fix is two upgrades. The
# advisory screen asks the opposite question — "what does this problem touch
# here" — so it merges every bucket that names the same advisory and then splits
# the answer the way it is triaged: affected components (or the asset itself when
# no component was ever attached) plus the occurrences behind them.

SETTLED_STATUSES = CLOSED_STATUSES


def _settled(finding: models.Finding) -> bool:
    """Closed has two spellings in this table and they are the same fact."""
    return (finding.status or "").lower() in SETTLED_STATUSES


def _advisory_rows(session: Session, ref: str) -> list[models.Vulnerability]:
    """Catalog rows that answer to this id, whichever column carries it."""
    needle = ref.strip().upper()
    return (session.query(models.Vulnerability)
            .filter(models.Vulnerability.cve_id.isnot(None))
            .filter(models.Vulnerability.cve_id == needle).all())


def _kev_detail(session: Session, cve_id: str | None) -> dict:
    """The KEV row is a catalog entry, not just a boolean: action and CWE matter."""
    if not cve_id:
        return {"known": False, "listed": False, "reason": "no CVE id"}
    row = session.get(models.KevEntry, cve_id.upper())
    if row is None:
        return {"known": True, "listed": False,
                "reason": "in no mirrored KEV catalogue"}
    return {
        "known": True, "listed": True,
        "name": row.name or row.title,
        "vendor": row.vendor, "product": row.product,
        "description": row.description,
        "required_action": row.required_action,
        "ransomware": row.ransomware, "cwes": row.cwes,
        "date_added": row.date_added, "due_date": row.due_date,
        "source": row.source,
        # Which catalogues say so. One publisher is an opinion; three agreeing is
        # the strongest statement this platform can make about exploitation.
        "sources": [item for item in (row.sources or "").split(",") if item.strip()],
        "exploitation_type": row.exploitation_type,
    }


def _advisory_dossier(session: Session, org: models.Organization, ref: str,
                      include_suppressed: bool = False) -> dict | None:
    """Everything the advisory screen prints, or None when nothing names it."""
    needle = ref.strip().lower()
    rows = [row for row in _groups(session, org, include_suppressed)
            if (row["cve_id"] or "").lower() == needle
            or row["signature"].lower() == needle]
    catalog = _advisory_rows(session, ref)
    if not rows and not catalog and session.get(models.KevEntry, ref.upper()) is None:
        return None

    cve_id = next((row["cve_id"] for row in rows if row["cve_id"]), None) \
        or (catalog[0].cve_id if catalog else ref.upper())

    # The findings behind every bucket, keyed so the affected table can be built
    # from the finding itself (asset attribution lives there, not in `locations`).
    finding_ids = [location["finding_id"] for row in rows for location in row["locations"]]
    findings: list[models.Finding] = []
    if finding_ids:
        findings = (session.query(models.Finding)
                    .filter(models.Finding.org_id == org.id,
                            models.Finding.id.in_(finding_ids)).all())

    descriptions = [row["title"] for row in rows if row["title"]] + \
                   [row.title for row in catalog if row.title]
    description = max(descriptions, key=len) if descriptions else None
    # The NVD-side ingest writes `CVE-…: <description>` as the title because a
    # finding row needs a self-describing title; on a page whose h1 is that id the
    # prefix is noise.
    if description:
        prefix = f"{cve_id}: "
        if description.startswith(prefix):
            description = description[len(prefix):]
    vectors = [row["cvss"]["vector"] for row in rows if row["cvss"]["vector"]] + \
              [row.cvss_vector for row in catalog if row.cvss_vector]
    observed_scores: list[float] = [
        float(row["cvss"]["score"]) for row in rows
        if isinstance(row["cvss"]["score"], (int, float))]
    url = next((row["url"] for row in rows if row["url"]), None) \
        or next((row.url for row in catalog if row.url), None)
    published = next((row.published for row in catalog if row.published), None)
    modified = next((row.modified for row in catalog if row.modified), None)

    projects: dict[str, models.Project] = {}
    components_cache: dict[str, models.Component] = {}
    components: dict[tuple, dict] = {}
    assets: dict[tuple, dict] = {}

    # How each package got into each build. "Affected: brotli 1.0.9" is only
    # actionable as "brotli came in through axios", and the walk is one query per
    # build — computed once per (build, package) pair, not once per finding.
    link_cache: dict[str, dict] = {}
    chain_cache: dict[tuple[str, str], list[dict]] = {}

    def links_for(version_id: str) -> dict:
        if version_id not in link_cache:
            link_cache[version_id] = links_of(session, version_id)
        return link_cache[version_id]

    def chain_for(version_id: str, component: models.Component) -> list[dict]:
        key = (version_id, component.id)
        if key not in chain_cache:
            chain_cache[key] = ancestry(session, version_id, component,
                                        links=links_for(version_id))
        return chain_cache[key]

    def project_of(project_id):
        if not project_id:
            return None
        if project_id not in projects:
            projects[project_id] = session.get(models.Project, project_id)
        return projects[project_id]

    for finding in findings:
        project = project_of(finding.project_id)
        component = None
        if finding.component_id:
            component = components_cache.get(finding.component_id)
            if component is None:
                component = session.get(models.Component, finding.component_id)
                if component is not None:
                    components_cache[component.id] = component
        version = (session.get(models.ProjectVersion, finding.last_seen_version_id)
                   if finding.last_seen_version_id else None)
        detail = _detail_of(finding)
        fixed = detail.get("fixed_version") if isinstance(detail.get("fixed_version"), str) else None
        severity = severity_vocab.canonical(finding.severity)
        # Two in-memory shapes carry the score: the SBOM ingest writes
        # `cvss_score`, the NVD runtime ingest writes `cvss`. Reading only one of
        # them printed "no CVSS score" on every runtime CVE.
        measured = detail.get("cvss_score")
        if not isinstance(measured, (int, float)):
            measured = detail.get("cvss")
        if isinstance(measured, (int, float)):
            observed_scores.append(float(measured))

        if component is not None:
            # A component is a package@version, so it is already per-version; the
            # build label is the project version that carries it.
            key = ("component", finding.project_id, component.id,
                   version.id if version else "")
        elif finding.asset_id:
            key = ("asset", finding.asset_id)
        else:
            key = ("project", finding.project_id)

        if key[0] == "asset":
            bucket = assets.setdefault(key, {
                "id": finding.asset_id,
                "asset": None,
                "project": ({"slug": project.slug, "name": project.name}
                            if project else None),
                "findings": 0, "open_findings": 0,
                "severity": "UNKNOWN", "fixed_versions": set(),
            })
            if bucket["asset"] is None:
                asset_row = session.get(models.Asset, finding.asset_id)
                if asset_row is not None:
                    bucket["asset"] = {"id": asset_row.id, "value": asset_row.value,
                                       "type": asset_row.type}
        else:
            bucket = components.setdefault(key, {
                "project": ({"slug": project.slug, "name": project.name}
                            if project else None),
                "component": ({"id": component.id, "name": component.name,
                               "version": component.version, "purl": component.purl,
                               "license": component.license}
                              if component is not None else None),
                "build": ({"id": version.id, "version": version.version}
                          if version is not None else None),
                "findings": 0, "open_findings": 0,
                "severity": "UNKNOWN", "fixed_versions": set(),
                # `direct` is the BOM's own claim; `chain` is the path that makes
                # "upgrade this package" a decision somebody can take.
                "direct": None, "chain": [],
            })
        bucket["findings"] += 1
        if key[0] != "asset" and component is not None and version is not None:
            link = links_for(version.id).get(component.id)
            bucket["direct"] = bool(link.is_direct) if link is not None else None
            bucket["chain"] = chain_for(version.id, component)
        if not _settled(finding):
            bucket["open_findings"] += 1
        if severity_vocab.rank(severity) < severity_vocab.rank(bucket["severity"]):
            bucket["severity"] = severity
        if fixed:
            bucket["fixed_versions"].add(fixed)

    def rank(row):
        return (severity_vocab.rank(row["severity"]), -row["open_findings"],
                (row.get("project") or {}).get("slug") or "",
                (row.get("component") or {}).get("name") or "",
                (row.get("build") or {}).get("version") or "")

    component_rows = []
    for bucket in sorted(components.values(), key=rank):
        bucket["fixed_versions"] = sorted(bucket["fixed_versions"])
        bucket["fixable"] = bool(bucket["fixed_versions"])
        component_rows.append(bucket)
    asset_rows = []
    for bucket in sorted(assets.values(), key=rank):
        bucket["fixed_versions"] = sorted(bucket["fixed_versions"])
        asset_rows.append(bucket)

    occurrences = []
    for finding in sorted(findings, key=lambda row: (severity_vocab.rank(
            severity_vocab.canonical(row.severity)), row.project_id or "")):
        project = project_of(finding.project_id)
        component = components_cache.get(finding.component_id) if finding.component_id else None
        version = (session.get(models.ProjectVersion, finding.last_seen_version_id)
                   if finding.last_seen_version_id else None)
        asset_row = session.get(models.Asset, finding.asset_id) if finding.asset_id else None
        detail = _detail_of(finding)
        occurrences.append({
            "id": finding.id,
            "title": finding.title,
            "severity": severity_vocab.canonical(finding.severity),
            "status": finding.status,
            "settled": _settled(finding),
            "project": project.slug if project else None,
            "component": component.name if component is not None else None,
            "component_version": component.version if component is not None else None,
            "component_id": component.id if component is not None else None,
            "build": version.version if version is not None else None,
            "asset": ({"id": asset_row.id, "value": asset_row.value}
                      if asset_row is not None else None),
            "tool": finding.tool,
            "path": finding.path,
            "fixed_version": (detail.get("fixed_version")
                              if isinstance(detail.get("fixed_version"), str) else None),
            "first_seen_at": finding.first_seen_at.isoformat() if finding.first_seen_at else None,
            "last_seen_at": finding.last_seen_at.isoformat() if finding.last_seen_at else None,
        })

    severity = _worst_severity([finding.severity for finding in findings])
    enrichment = _enrichment(session, cve_id)
    enrichment["kev"].update(_kev_detail(session, cve_id))
    reachable = bool(asset_rows) or any(
        row["project"] for row in component_rows)
    project_ids = {finding.project_id for finding in findings if finding.project_id}
    score = max(observed_scores) if observed_scores else None
    # A score read off the vector is not a score the scanner quoted; the page says
    # which one it has.
    quoted = any(isinstance(_detail_of(finding).get("cvss_score"), (int, float))
                 for finding in findings) or any(
        row["cvss"]["known"] and not row["cvss"].get("derived") for row in rows)
    return {
        "cve_id": cve_id,
        "ref": ref,
        "signature": (rows[0]["signature"] if rows else cve_id),
        "title": description,
        "description": description,
        "severity": severity,
        "cvss": {"known": score is not None or bool(vectors),
                 "score": score,
                 "derived": score is not None and not quoted,
                 "vector": vectors[0] if vectors else None,
                 "reason": None if (score is not None or vectors)
                 else "the scanner that reported it stated no CVSS score"},
        "url": url,
        "published": published.isoformat() if published else None,
        "modified": modified.isoformat() if modified else None,
        "sources": sorted({row.source for row in catalog if row.source}),
        "advisory_rows": len(catalog),
        "enrichment": enrichment,
        "risk": _risk_of(severity, enrichment, reachable),
        "affected": {
            "components": component_rows,
            "assets": asset_rows,
            "totals": {"rows": len(component_rows),
                       "components": len({row["component"]["id"] for row in component_rows
                                          if row["component"]}),
                       "project_level": sum(1 for row in component_rows if not row["component"]),
                       "projects": len(project_ids),
                       "builds": len({row["build"]["id"] for row in component_rows
                                      if row["build"]}),
                       "assets": len(asset_rows)},
        },
        "findings": occurrences,
        "counters": {
            "findings": len(findings),
            "open": sum(1 for finding in findings if not _settled(finding)),
            "fixable": bool(component_rows and all(row["fixable"] for row in component_rows)),
            "kev": int(enrichment["kev"]["listed"]),
        },
        # Absence is stated with its reason: "no finding" is not "not affected".
        "coverage": {
            "estate": ("has findings" if findings else
                       "no finding in this organization names this advisory"),
            "note": (None if findings else
                     "The estate list is built from findings, so an empty answer means "
                     "no scan here reported it — not that the software is unaffected."),
            "grouping": "one row per (project, component, build); assets answer for "
                        "findings with no component",
        },
    }



@router.get("/vulnerabilities")
def list_vulnerabilities(project: str | None = Query(default=None),
                         vector: str | None = Query(default=None),
                         severity: str | None = Query(default=None),
                         status_filter: str | None = Query(default=None, alias="status"),
                         kev_only: bool = Query(default=False),
                         q: str | None = Query(default=None),
                         include_suppressed: bool = Query(default=False),
                         limit: int = Query(default=200, ge=1, le=1000),
                         offset: int = Query(default=0, ge=0),
                         org: models.Organization = Depends(auth.require_org),
                         session: Session = Depends(get_session)):
    """Every vulnerability once, with the subjects that carry it.

    The row is the vulnerability, not the package: `components`, `projects`,
    `versions` and `locations` are the findings that connect it to our estate,
    and the advisory page is where each of those is a line.
    """
    rows = _groups(session, org, include_suppressed, by="signature")
    if project:
        project_row = projects_ref.by_ref(session, org.id, project)
        if project_row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
        rows = [row for row in rows
                if project_row.id in {p["id"] for p in row["projects"]}]
    if vector:
        rows = [row for row in rows if row["vector"] == vector]
    if severity:
        wanted = severity_vocab.canonical(severity)
        rows = [row for row in rows if row["severity"] == wanted]
    if status_filter:
        rows = [row for row in rows if status_filter in row["statuses"]]
    if kev_only:
        rows = [row for row in rows if row["enrichment"]["kev"]["listed"]]
    if q:
        needle = q.strip().lower()
        rows = [row for row in rows
                if needle in (row["signature"] or "").lower()
                or needle in (row["title"] or "").lower()
                or needle in (row["vector_label"] or "").lower()]

    by_vector: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_risk: dict[str, int] = {}
    for row in rows:
        by_vector[row["vector"]] = by_vector.get(row["vector"], 0) + 1
        by_severity[row["severity"]] = by_severity.get(row["severity"], 0) + 1
        by_risk[row["exposure"]["label"]] = by_risk.get(row["exposure"]["label"], 0) + 1
    total = len(rows)
    return {
        "data": rows[offset:offset + limit],
        "total": total,
        "limit": limit,
        "offset": offset,
        "counters": {
            "vulnerabilities": total,
            "findings": sum(row["findings"] for row in rows),
            "by_vector": by_vector,
            "by_severity": by_severity,
            "by_risk": by_risk,
            "fixable": sum(1 for row in rows if row["fix"]["available"]),
            "kev": sum(1 for row in rows if row["enrichment"]["kev"]["listed"]),
            "reachable": sum(1 for row in rows if row["reachable"]),
        },
        "coverage": {
            "vectors": list(VECTOR_LABELS.keys()),
            "exploit_feed": ("connected" if any(row["enrichment"]["kev"]["known"]
                                                for row in rows)
                             else "not connected (KEV/EPSS empty)"),
            "grouping": "one row per (vector, signature, component)",
        },
    }


@router.get("/vulnerabilities/meta/summary")
@router.get("/vulnerabilities/summary")
def summary(org: models.Organization = Depends(auth.require_org),
            session: Session = Depends(get_session)):
    """Counters for the dashboard and the projects list."""
    rows = _groups(session, org, include_suppressed=False)
    return {"data": {
        "vulnerabilities": len(rows),
        "findings": sum(row["findings"] for row in rows),
        "kev": sum(1 for row in rows if row["enrichment"]["kev"]["listed"]),
        "fixable": sum(1 for row in rows if row["fix"]["available"]),
        "by_vector": {vector: sum(1 for row in rows if row["vector"] == vector)
                      for vector in VECTOR_LABELS},
        "by_severity": {level: sum(1 for row in rows if row["severity"] == level)
                        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")},
        "by_risk": {label: sum(1 for row in rows if row["exposure"]["label"] == label)
                    for label in ("critical", "high", "medium", "low")},
    }}


@router.get("/vulnerabilities/advisory/{ref}")
def get_advisory(ref: str,
                 include_suppressed: bool = Query(default=False),
                 org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    """One advisory as a page: what it says, and everything here it touches.

    Unlike `GET /vulnerabilities/{ref}` — which answers the list's row — this
    merges every bucket naming the same advisory, so a CVE present in three
    packages answers once with three affected components.
    """
    dossier = _advisory_dossier(session, org, ref, include_suppressed)
    if dossier is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "no advisory row, KEV entry or finding in this organization matches that id")
    return {"data": dossier}


@router.get("/vulnerabilities/{ref}")
def get_vulnerability(ref: str,
                      include_suppressed: bool = Query(default=False),
                      org: models.Organization = Depends(auth.require_org),
                      session: Session = Depends(get_session)):
    """One problem with every occurrence, or 404 when it affects nothing here."""
    row = _match(_groups(session, org, include_suppressed), ref)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            "no finding in this organization matches that vulnerability")
    return {"data": row}


class StatusIn(BaseModel):
    status: str = Field(min_length=1, max_length=32)
    reason: str | None = Field(default=None, max_length=2000)


@router.patch("/vulnerabilities/{ref}/status")
def set_status(ref: str, payload: StatusIn,
               org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    """Move every finding of this problem at once.

    A vulnerability has one lifecycle even when it has twelve occurrences; making
    the operator click twelve times is how a queue stops being worked.
    """
    allowed = {"open", "acknowledged", "resolved", "false_positive", "accepted_risk"}
    if payload.status not in allowed:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"status must be one of {sorted(allowed)}")
    row = _match(_groups(session, org, include_suppressed=True), ref)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "vulnerability not found")
    now = models.utcnow()
    touched = 0
    for location in row["locations"]:
        finding = session.get(models.Finding, location["finding_id"])
        if finding is None or finding.status == "suppressed":
            continue
        finding.status = payload.status
        finding.status_reason = payload.reason
        finding.status_changed_at = now
        finding.updated_at = now
        touched += 1
    _audit_log(session, org.id, "operator", f"vulnerability.{payload.status}",
               "vulnerability", row["id"], payload.reason)
    session.commit()
    return {"data": {"id": row["id"], "status": payload.status, "findings": touched}}


class BulkPreviewIn(BaseModel):
    finding_ids: list[str] = Field(min_length=1, max_length=1000)
    status: str


@router.post("/vulnerabilities/{ref}/bulk-preview")
def bulk_preview(ref: str, payload: BulkPreviewIn = None,
                 org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    """Preview a grouped status change without writing anything.

    The preview and the apply path share the selection logic, so the numbers a
    reader approves are the numbers that would change. Suppressed findings are
    skipped: their disposition belongs to the suppression rule.
    """
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    from backend.app.routers.findings import ALLOWED_STATUSES
    if payload.status not in ALLOWED_STATUSES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"status must be one of {sorted(ALLOWED_STATUSES)}")
    will_change, already, skipped = [], [], []
    for finding_id in payload.finding_ids:
        finding = session.get(models.Finding, finding_id)
        if finding is None or finding.org_id != org.id:
            skipped.append({"finding_id": finding_id,
                            "reason": "not found in this organization"})
            continue
        if finding.status == "suppressed":
            skipped.append({"finding_id": finding_id,
                            "reason": "suppressed findings change with their rule"})
            continue
        if finding.status == payload.status:
            already.append(finding_id)
            continue
        will_change.append({"id": finding.id, "from": finding.status,
                            "to": payload.status, "project": finding.project_id})
    return {"data": {"ref": ref, "target_status": payload.status,
                     "would_change": len(will_change), "unchanged": len(already),
                     "skipped": skipped, "findings": will_change,
                     "requires": "write role (viewer cannot change status)"}}


@router.post("/vulnerabilities/{ref}/bulk-status")
def bulk_status(ref: str, payload: BulkPreviewIn = None,
                actor: str = Query(default="api"),
                org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    """Apply the previewed change to exactly the findings it listed."""
    from backend.app.routers.findings import ALLOWED_STATUSES
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.status not in ALLOWED_STATUSES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"status must be one of {sorted(ALLOWED_STATUSES)}")
    changed, skipped = [], []
    for finding_id in payload.finding_ids:
        finding = session.get(models.Finding, finding_id)
        if finding is None or finding.org_id != org.id:
            skipped.append(finding_id)
            continue
        if finding.status in {"suppressed", payload.status}:
            skipped.append(finding_id)
            continue
        finding.status = payload.status
        finding.status_changed_at = models.utcnow()
        finding.updated_at = finding.status_changed_at
        _audit_log(session, org.id, actor, "finding.status_changed", "finding",
                   finding.id, f"{ref}: {payload.status}")
        changed.append(finding.id)
    session.commit()
    return {"data": {"ref": ref, "status": payload.status,
                     "changed": len(changed), "finding_ids": changed,
                     "skipped": skipped}}

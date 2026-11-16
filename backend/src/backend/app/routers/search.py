"""Estate search: one filter language over every entity the console carries.

The topbar used to search screens only. That answers "where do I go", never
"who ships node@20" or "which project owns this domain" — the questions an
operator actually types. This endpoint reads projects, packages, assets,
advisory groups and findings in one round trip and returns typed hits the
console can turn into deep links.

Grammar (space separated, `key:value`; unknown keys are dependencies, which is
why `node:20` works without a prefix):

    node:20            dependency name + version line (also `dep:node@20`)
    @scope/pkg@1.2     dependency, scoped npm form
    project:aurea      only that project (slug or name)
    severity:critical  filter advisories/findings (aliases canonicalised)
    domain:api.x.com   asset/domain value
    cve:CVE-2024-1234  advisory id
    type:asset         one entity kind: project | component | asset |
                       vulnerability | finding (aliases: dep, domain, cve)
    anything else      free text, matched per entity

Every token narrows (AND). Results are grouped by kind with the real total
before the per-kind cap, so the UI can say "6 of 23" instead of pretending the
list is complete.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from fastapi import APIRouter, Depends, Query
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from backend.app import auth, models, severity as severity_vocab
from backend.app.db import get_session

router = APIRouter(prefix="/api/v1", tags=["search"])

KINDS = ("project", "component", "version", "asset", "vulnerability", "finding")

_KIND_ALIASES = {
    "project": "project", "projects": "project", "app": "project",
    "component": "component", "components": "component",
    "dependency": "component", "dependencies": "component",
    "dep": "component", "pkg": "component", "package": "component",
    # A project version is a build: "which build carries this" is its own answer,
    # separate from the package rows that hang off it.
    "version": "version", "versions": "version", "build": "version",
    "builds": "version", "release": "version",
    "asset": "asset", "assets": "asset", "domain": "asset", "host": "asset",
    "vulnerability": "vulnerability", "vulnerabilities": "vulnerability",
    "vuln": "vulnerability", "cve": "vulnerability", "advisory": "vulnerability",
    "finding": "finding", "findings": "finding",
}

# `key:value` keys the grammar reserves for filters. Anything else with a colon
# is a package and a version line — `node:20` must not need a prefix.
_RESERVED = {"type", "kind", "project", "severity", "dep", "pkg", "package",
             "asset", "domain", "host", "cve", "vuln", "advisory"}

_TOKEN = re.compile(r'"[^"]*"|\S+')
_SCOPED_DEP = re.compile(r"^(@[^/:\s]+/[^@:\s]+)(?:[@:](.+))?$")
_NUMERIC = re.compile(r"\d+(?:\.\d+)*")


@dataclass
class ParsedQuery:
    text: list[str] = field(default_factory=list)
    deps: list[tuple[str, str | None]] = field(default_factory=list)
    kinds: set[str] = field(default_factory=set)
    project: str | None = None
    severity: str | None = None
    domain: str | None = None
    cve: str | None = None


def _dep(token: str) -> tuple[str, str | None]:
    """`node:20`, `lodash@4.17.21`, `@scope/pkg@1.2` → (name, version|None)."""
    token = token.strip()
    if token.startswith("@"):
        match = _SCOPED_DEP.match(token)
        if match:
            return match.group(1), (match.group(2) or None)
    name, sep, version = token.rpartition("@")
    if not sep:
        name, sep, version = token.partition(":")
    name = name.strip()
    version = (version or "").strip() or None
    return name, version


def parse_query(raw: str) -> ParsedQuery:
    """Pure, so the grammar can be tested without a database."""
    parsed = ParsedQuery()
    for match in _TOKEN.findall(raw or ""):
        quoted = match.startswith('"') and match.endswith('"') and len(match) > 1
        token = match[1:-1] if quoted else match
        if not token:
            continue
        # npm/UPM package forms, which carry `@` instead of `:` in the token.
        if not quoted and token.startswith("@") and "/" in token:
            parsed.deps.append(_dep(token))
            continue
        if quoted or ":" not in token or token.startswith(("http://", "https://")):
            # `lodash@4.17.21` is a package; an email address is a word.
            if not quoted and re.match(r"^[^@\s]+@[v\d^~<>=]", token):
                parsed.deps.append(_dep(token))
            else:
                parsed.text.append(token)
            continue
        key, _, value = token.partition(":")
        key, value = key.lower(), value.strip()
        if not value:
            parsed.text.append(token)
        elif key in ("type", "kind"):
            kind = _KIND_ALIASES.get(value.lower())
            if kind:
                parsed.kinds.add(kind)
            else:
                parsed.text.append(value)
        elif key == "project":
            parsed.project = value
        elif key == "severity":
            parsed.severity = severity_vocab.canonical(value)
        elif key in ("dep", "pkg", "package"):
            parsed.deps.append(_dep(value))
        elif key in ("asset", "domain", "host"):
            parsed.domain = value
        elif key in ("cve", "vuln", "advisory"):
            parsed.cve = value.upper()
        elif key == "owner":
            parsed.text.append(value)
        else:
            # `node:20`: not a reserved key, so the whole token is a dependency.
            parsed.deps.append(_dep(token))
    return parsed


def _version_matches(stored: str | None, wanted: str) -> bool:
    """Does a stored version belong to the requested release line?

    `20` must find `20.11.1`, `20-alpine` and `>=20 <21`, and must not find
    `4.1.11` or `24.0.10`. A range constraint is read by its leading number,
    which is the line it pins; non-numeric wants fall back to substring.
    """
    if not stored:
        return False
    value = stored.strip().lower()
    want = wanted.strip().lower().lstrip("v=<>~^ ")
    if not want:
        return True
    if value == want or value.startswith((want + ".", want + "-", want + " ")):
        return True
    if _NUMERIC.fullmatch(want):
        lead = _NUMERIC.match(value.lstrip("=<>~^ "))
        if lead:
            return lead.group(0) == want or lead.group(0).startswith(want + ".")
    return want in value


def _like(column, term: str):
    return column.ilike(f"%{term}%")


def _clip(value: str | None, size: int = 140) -> str | None:
    """One line of an advisory body, not the body itself: a dropdown row is a
    pointer, and the ficha is one click away."""
    if not value:
        return None
    text = " ".join(str(value).split())
    return text if len(text) <= size else text[:size].rstrip() + "…"


def _iso(value) -> str | None:
    """Every hit carries when it entered the platform, in one shape.

    "Registrado" is not the same fact for every kind — an asset was discovered, a
    build was imported, a package first arrived with some SBOM — so the column is
    named for what it is instead of being flattened into a vague `date`.
    """
    return value.isoformat() if value is not None else None


def _advisory_summary(signature: str, title: str | None) -> str | None:
    """The row already prints the id; repeating `CVE-…:` before the sentence
    spends the one line of summary on punctuation."""
    if not title:
        return None
    text = title.strip()
    if text.upper().startswith(signature.upper()):
        text = text[len(signature):].lstrip(": -–—").strip() or title
    return _clip(text)


def _text_match(fields, terms):
    """Every free term must appear in at least one of the row's fields."""
    filters = []
    for term in terms:
        filters.append(or_(*[_like(column, term) for column in fields]))
    return filters


def _project_row(session: Session, org_id: str, ref: str):
    query = session.query(models.Project).filter_by(org_id=org_id)
    row = query.filter(models.Project.slug == ref).one_or_none()
    if row is None:
        row = query.filter(func.lower(models.Project.name) == ref.lower()).first()
    return row


@router.get("/search")
def estate_search(q: str = Query(default="", max_length=200),
                  # The dropdown asks for 6; the results page asks for the lot. The
                  # ceiling is the only thing that changes — the shape of a hit does
                  # not, so one endpoint serves both screens.
                  limit: int = Query(default=6, ge=1, le=200),
                  org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    parsed = parse_query(q)
    scope_project = (_project_row(session, org.id, parsed.project)
                     if parsed.project else None)
    # A `project:` that names nothing must not silently widen the search to the
    # whole estate: an empty answer is the honest one.
    if parsed.project and scope_project is None:
        return {"query": q, "parsed": _parsed_data(parsed), "groups": [],
                "total": 0}

    projects = (session.query(models.Project).filter_by(org_id=org.id)
                .order_by(models.Project.name).all())
    project_by_id = {row.id: row for row in projects}
    if scope_project is not None:
        projects = [scope_project]
        project_by_id = {scope_project.id: scope_project}

    # ── dependencies: which packages match, and where they ship ──────────────
    dep_component_ids: set[str] = set()
    dep_project_ids: list[set[str]] = []
    dep_component_rows: dict[str, models.Component] = {}
    for name, version in parsed.deps:
        rows = (session.query(models.Component)
                .filter(models.Component.org_id == org.id,
                        func.lower(models.Component.name) == name.lower()).all())
        rows = [row for row in rows if not version or _version_matches(row.version, version)]
        for row in rows:
            dep_component_rows[row.id] = row
        dep_component_ids.update(row.id for row in rows)
        if not rows:
            dep_project_ids.append(set())
            continue
        found = {project_id for project_id, in
                 (session.query(models.ProjectVersion.project_id)
                  .join(models.VersionComponent,
                        models.VersionComponent.project_version_id == models.ProjectVersion.id)
                  .filter(models.VersionComponent.component_id.in_([r.id for r in rows]))
                  .distinct().all())}
        dep_project_ids.append(found)
    dep_project_set = (set.intersection(*dep_project_ids) if dep_project_ids else None)

    groups = []
    kinds = parsed.kinds or set(KINDS)

    # ── projects ────────────────────────────────────────────────────────────
    if "project" in kinds:
        hits = []
        for project in projects:
            if dep_project_set is not None and project.id not in dep_project_set:
                continue
            if parsed.domain and not _project_has_asset(session, org.id, project.id,
                                                       parsed.domain):
                continue
            if parsed.severity and not _project_has_severity(session, project.id,
                                                             parsed.severity):
                continue
            haystack = " ".join(filter(None, (project.name, project.slug,
                                              project.group_name, project.description,
                                              project.owner))).lower()
            if not all(term.lower() in haystack for term in parsed.text):
                continue
            hits.append({"kind": "project", "id": project.id, "title": project.name,
                         "subtitle": " · ".join(filter(None, (project.slug,
                                                              project.group_name))),
                         "slug": project.slug, "group": project.group_name,
                         "owner": project.owner,
                         "registered_at": _iso(project.created_at)})
        groups.append({"kind": "project", "total": len(hits), "items": hits[:limit]})

    # ── components (dependencies) ───────────────────────────────────────────
    if "component" in kinds:
        groups.append(_component_group(session, org, parsed, limit, project_by_id,
                                       dep_component_ids, dep_component_rows))

    # ── project versions (the builds) ───────────────────────────────────────
    if "version" in kinds:
        groups.append(_version_group(session, org, parsed, limit, project_by_id))

    # ── assets / domains ────────────────────────────────────────────────────
    if "asset" in kinds:
        groups.append(_asset_group(session, org, parsed, limit, project_by_id))

    # ── advisory groups (the vulnerabilities screen's rows) ─────────────────
    if "vulnerability" in kinds:
        groups.append(_vulnerability_group(session, org, parsed, limit, project_by_id,
                                           dep_component_ids))

    # ── findings ────────────────────────────────────────────────────────────
    if "finding" in kinds:
        groups.append(_finding_group(session, org, parsed, limit, project_by_id,
                                     dep_component_ids))

    return {"query": q, "parsed": _parsed_data(parsed), "groups": groups,
            "total": sum(group["total"] for group in groups)}


def _parsed_data(parsed: ParsedQuery) -> dict:
    return {"text": parsed.text, "kinds": sorted(parsed.kinds),
            "deps": [{"name": name, "version": version}
                     for name, version in parsed.deps],
            "project": parsed.project, "severity": parsed.severity,
            "domain": parsed.domain, "cve": parsed.cve}


def _project_has_asset(session: Session, org_id: str, project_id: str,
                       needle: str) -> bool:
    return (session.query(models.Asset.id)
            .filter(models.Asset.org_id == org_id,
                    models.Asset.project_id == project_id,
                    _like(models.Asset.value, needle)).first()) is not None


def _project_has_severity(session: Session, project_id: str, severity: str) -> bool:
    return (session.query(models.Finding.id)
            .filter(models.Finding.project_id == project_id,
                    models.Finding.severity.in_(severity_vocab.raw_variants(severity)))
            .first()) is not None


def _component_group(session: Session, org: models.Organization, parsed: ParsedQuery,
                     limit: int, project_by_id: dict,
                     dep_component_ids: set[str],
                     dep_component_rows: dict) -> dict:
    rows: dict[str, models.Component] = {}
    if parsed.deps:
        rows.update(dep_component_rows)
        # Free words still narrow: `node:20 vite` is "the project that ships
        # both", never whichever side matches.
        for component_id, row in list(rows.items()):
            haystack = " ".join(filter(None, (row.name, row.purl, row.version,
                                              row.identity_key))).lower()
            if not all(term.lower() in haystack for term in parsed.text):
                rows.pop(component_id)
    else:
        query = session.query(models.Component).filter_by(org_id=org.id)
        for constraint in _text_match((models.Component.name, models.Component.purl,
                                       models.Component.version,
                                       models.Component.identity_key), parsed.text):
            query = query.filter(constraint)
        if parsed.domain:
            query = query.filter(or_(_like(models.Component.name, parsed.domain),
                                     _like(models.Component.purl, parsed.domain)))
        rows.update({row.id: row for row in query.order_by(
            models.Component.name, models.Component.version).limit(limit * 25).all()})

    if not rows:
        return {"kind": "component", "total": 0, "items": []}

    links = (session.query(models.VersionComponent, models.ProjectVersion,
                           models.Project)
             .join(models.ProjectVersion,
                   models.VersionComponent.project_version_id == models.ProjectVersion.id)
             .join(models.Project,
                   models.ProjectVersion.project_id == models.Project.id)
             .filter(models.VersionComponent.component_id.in_(list(rows)),
                     models.ProjectVersion.project_id.in_(list(project_by_id)))
             .all())
    app_components = {}
    if links:
        app_components = {row.id: row for row in
                          (session.query(models.ApplicationComponent)
                           .filter(models.ApplicationComponent.id.in_(
                               [version_row.component_id for _, version_row, _
                                in links if version_row.component_id]))
                           .all())}

    grouped: dict[tuple[str, str | None], dict] = {}
    for link, version_row, project in links:
        component = rows.get(link.component_id)
        if component is None:
            continue
        key = (component.name or "", component.version)
        item = grouped.setdefault(key, {
            "kind": "component", "id": component.id,
            "title": component.name or component.identity_key,
            "version": component.version, "purl": component.purl,
            "direct": bool(link.is_direct),
            "registered_at": _iso(component.created_at),
            "projects": [], "_slugs": set(),
        })
        if project.slug in item["_slugs"]:
            continue
        item["_slugs"].add(project.slug)
        app_component = app_components.get(version_row.component_id) \
            if version_row.component_id else None
        item["projects"].append({
            "slug": project.slug, "name": project.name,
            "component": app_component.slug if app_component else None,
            "component_name": app_component.name if app_component else None,
            "version": version_row.version, "version_id": version_row.id,
        })

    items = []
    for item in grouped.values():
        item["_slugs"] = len(item.pop("_slugs"))
        first = item["projects"][0]
        item.update({"project_slug": first["slug"], "project_name": first["name"],
                     "component": first["component"], "version_label": first["version"],
                     "version_id": first["version_id"],
                     "project_count": len(item["projects"])})
        item["subtitle"] = " · ".join(filter(None, (item.get("version"),
                                                    first["name"])))
        items.append(item)
    items.sort(key=lambda item: (not item["direct"],
                                 not (parsed.deps and item["title"].lower()
                                      == parsed.deps[0][0].lower()),
                                 item["title"].lower()))
    return {"kind": "component", "total": len(items), "items": items[:limit]}


def _version_group(session: Session, org: models.Organization, parsed: ParsedQuery,
                   limit: int, project_by_id: dict) -> dict:
    """The builds themselves: "which version of Aurea is on the platform".

    A package hit answers "who ships lodash@4"; a version hit answers "which build
    exists, since when, and where it lives". The date is the import's own
    `created_at` — when the row entered the estate — not the repository's tag,
    which the platform never invents.
    """
    # A dependency-only query (`node:20`) has nothing to say about builds, and
    # answering it with every version in the estate reads as a match.
    if not parsed.text and parsed.deps and "version" not in parsed.kinds:
        return {"kind": "version", "total": 0, "items": []}
    query = (session.query(models.ProjectVersion, models.Project)
             .join(models.Project,
                   models.ProjectVersion.project_id == models.Project.id)
             .filter(models.ProjectVersion.project_id.in_(list(project_by_id))))
    for term in parsed.text:
        query = query.filter(or_(_like(models.ProjectVersion.version, term),
                                 _like(models.Project.name, term),
                                 _like(models.Project.slug, term)))
    total = query.count()
    rows = (query.order_by(models.ProjectVersion.created_at.desc())
            .limit(limit * 4).all())
    component_ids = [version.component_id for version, _project in rows
                     if version.component_id]
    components = {}
    if component_ids:
        components = {row.id: row for row in
                      (session.query(models.ApplicationComponent)
                       .filter(models.ApplicationComponent.id.in_(component_ids)).all())}
    items, seen = [], set()
    for version, project in rows:
        if (project.id, version.version, version.component_id) in seen:
            continue
        seen.add((project.id, version.version, version.component_id))
        component = (components.get(version.component_id)
                     if version.component_id else None)
        items.append({
            "kind": "version", "id": version.id, "title": version.version,
            "version": version.version, "version_id": version.id,
            "project_slug": project.slug, "project_name": project.name,
            "component": component.slug if component else None,
            "component_name": component.name if component else None,
            "subtitle": " · ".join(filter(None, (
                project.name, component.name if component else None,
                None if component else "project-wide"))),
            "registered_at": _iso(version.created_at),
        })
        if len(items) >= limit:
            break
    return {"kind": "version", "total": total, "items": items}


def _asset_group(session: Session, org: models.Organization, parsed: ParsedQuery,
                 limit: int, project_by_id: dict) -> dict:
    terms = list(parsed.text)
    if parsed.domain:
        terms.append(parsed.domain)
    # A dependency-only query (`node:20`) has nothing to say about assets, and
    # returning the whole inventory under it reads as a match.
    if not terms:
        return {"kind": "asset", "total": 0, "items": []}
    query = (session.query(models.Asset)
             .filter(models.Asset.org_id == org.id,
                     models.Asset.archived_at.is_(None))
             .filter(models.Asset.project_id.in_(list(project_by_id))))
    for term in terms:
        query = query.filter(or_(_like(models.Asset.value, term),
                                 _like(models.Asset.detail, term),
                                 _like(models.Asset.type, term),
                                 _like(models.Asset.owner, term)))
    total = query.count()
    rows = query.order_by(models.Asset.last_seen_at.desc()).limit(limit).all()
    items = []
    for row in rows:
        project = project_by_id.get(row.project_id) if row.project_id else None
        items.append({
            "kind": "asset", "id": row.id, "title": row.value,
            "asset_type": row.type, "owner": row.owner,
            "project_slug": project.slug if project else None,
            "project_name": project.name if project else None,
            "registered_at": _iso(row.discovered_at),
            "last_seen_at": _iso(row.last_seen_at),
        })
    return {"kind": "asset", "total": total, "items": items}


def _vulnerability_group(session: Session, org: models.Organization,
                         parsed: ParsedQuery, limit: int, project_by_id: dict,
                         dep_component_ids: set[str]) -> dict:
    query = (session.query(models.Finding, models.Vulnerability)
             .join(models.Vulnerability,
                   models.Finding.vulnerability_id == models.Vulnerability.id)
             .filter(models.Finding.org_id == org.id,
                     models.Finding.status != "suppressed"))
    query = _scope_findings(query, parsed, project_by_id, dep_component_ids)
    if parsed.severity:
        query = query.filter(models.Finding.severity.in_(
            severity_vocab.raw_variants(parsed.severity)))
    for constraint in _text_match((models.Vulnerability.cve_id,
                                   models.Vulnerability.source_id,
                                   models.Vulnerability.title), parsed.text):
        query = query.filter(constraint)
    if parsed.cve:
        query = query.filter(or_(_like(models.Vulnerability.cve_id, parsed.cve),
                                 _like(models.Vulnerability.source_id, parsed.cve)))

    buckets: dict[str, dict] = {}
    for finding, advisory in query.all():
        signature = advisory.cve_id or advisory.source_id
        bucket = buckets.setdefault(signature, {
            "kind": "vulnerability", "id": signature, "title": signature,
            "subtitle": _advisory_summary(signature, advisory.title),
            "severity": "UNKNOWN", "findings": 0,
            "url": advisory.url, "_projects": {}, "_rank": 99, "_last": None,
        })
        bucket["findings"] += 1
        seen_at = row_last_seen(finding)
        if seen_at and (bucket["_last"] is None or seen_at > bucket["_last"]):
            bucket["_last"] = seen_at
        bucket["_rank"] = min(bucket["_rank"], severity_vocab.rank(finding.severity))
        if severity_vocab.rank(finding.severity) < severity_vocab.rank(bucket["severity"]):
            bucket["severity"] = severity_vocab.canonical(finding.severity)
        project = project_by_id.get(finding.project_id)
        if project is not None:
            bucket["_projects"][project.slug] = project.name

    items = []
    for bucket in buckets.values():
        bucket["projects"] = [{"slug": slug, "name": name}
                              for slug, name in bucket.pop("_projects").items()]
        rank = bucket.pop("_rank")
        bucket["last_seen_at"] = _iso(bucket.pop("_last"))
        items.append((rank, -bucket["findings"], bucket))
    items.sort(key=lambda item: (item[0], item[1], item[2]["id"]))
    ordered = [item[2] for item in items]
    return {"kind": "vulnerability", "total": len(ordered), "items": ordered[:limit]}


def _finding_group(session: Session, org: models.Organization, parsed: ParsedQuery,
                   limit: int, project_by_id: dict,
                   dep_component_ids: set[str]) -> dict:
    query = (session.query(models.Finding)
             .outerjoin(models.Component,
                        models.Component.id == models.Finding.component_id)
             .filter(models.Finding.org_id == org.id))
    query = _scope_findings(query, parsed, project_by_id, dep_component_ids)
    if parsed.severity:
        query = query.filter(models.Finding.severity.in_(
            severity_vocab.raw_variants(parsed.severity)))
    for constraint in _text_match((models.Finding.title, models.Finding.detail,
                                   models.Finding.rule_id, models.Finding.path,
                                   models.Finding.cwe, models.Finding.endpoint,
                                   models.Component.name, models.Component.purl),
                                  parsed.text):
        query = query.filter(constraint)
    if parsed.cve:
        advisory_ids = select(models.Vulnerability.id).where(
            or_(_like(models.Vulnerability.cve_id, parsed.cve),
                _like(models.Vulnerability.source_id, parsed.cve)))
        query = query.filter(models.Finding.vulnerability_id.in_(advisory_ids))

    total = query.count()
    severity_order = case(
        {value: index for index, value in enumerate(severity_vocab.SEVERITIES)},
        value=models.Finding.severity, else_=99)
    rows = (query.order_by(severity_order, models.Finding.last_seen_at.desc())
            .limit(limit * 4).all())
    advisories = {}
    advisory_ids = [row.vulnerability_id for row in rows if row.vulnerability_id]
    if advisory_ids:
        advisories = {row.id: row for row in
                      (session.query(models.Vulnerability)
                       .filter(models.Vulnerability.id.in_(advisory_ids)).all())}
    components = {}
    component_ids = [row.component_id for row in rows if row.component_id]
    if component_ids:
        components = {row.id: row for row in
                      (session.query(models.Component)
                       .filter(models.Component.id.in_(component_ids)).all())}

    items = []
    seen = set()
    for row in rows:
        project = project_by_id.get(row.project_id)
        component = components.get(row.component_id) if row.component_id else None
        advisory = advisories.get(row.vulnerability_id) if row.vulnerability_id else None
        if component is None and advisory is None:
            continue
        # The same advisory lands once per package version in one build; a
        # dropdown repeats it six times and hides the rest of the estate.
        key = (row.title, component.name if component else None,
               component.version if component else None, row.project_id)
        if key in seen:
            continue
        seen.add(key)
        items.append({
            "kind": "finding", "id": row.id,
            "title": _clip(row.title or (advisory.title if advisory else None)
                           or row.rule_id, 120),
            "severity": severity_vocab.canonical(row.severity),
            "status": row.status, "finding_kind": row.kind,
            "cve": advisory.cve_id if advisory else None,
            "component": component.name if component else None,
            "component_version": component.version if component else None,
            "project_slug": project.slug if project else None,
            "project_name": project.name if project else None,
            "subtitle": " · ".join(filter(None, (
                component.name if component else None,
                project.slug if project else None))),
            "registered_at": _iso(row.created_at),
            "last_seen_at": _iso(row.last_seen_at),
        })
        if len(items) >= limit:
            break
    return {"kind": "finding", "total": total, "items": items}


def row_last_seen(finding: models.Finding):
    """Aware datetimes only: mixing naive and aware raises on comparison."""
    value = getattr(finding, "last_seen_at", None) or getattr(finding, "created_at", None)
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=None)


def _scope_findings(query, parsed: ParsedQuery, project_by_id: dict,
                    dep_component_ids: set[str]):
    """The two scopes both findings and advisory groups share."""
    if parsed.project:
        query = query.filter(models.Finding.project_id.in_(list(project_by_id)))
    if parsed.deps:
        query = query.filter(models.Finding.component_id.in_(list(dep_component_ids or [""])))
    return query

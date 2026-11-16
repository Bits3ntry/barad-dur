"""B3: intelligence — KEV/EPSS feeds, VEX statements, advisory reconcile."""
import csv
import datetime
import io
import json
import urllib.request

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import advisory_names, auth, kev_feeds, models
from backend.app.db import get_session
from backend.app.vulns import vulnerability_fingerprint
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1", tags=["intelligence"])

# The catalogues live in `kev_feeds`: CISA is the reference, but it is not the only
# publisher of "this CVE is being exploited". `fetch_kev` keeps its old name and
# shape because a dozen call sites and tests speak it.
KEV_URL = kev_feeds.CISA_URL
EPSS_URL = "https://api.first.org/data/v1/epss"

VEX_STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}


def fetch_kev(timeout: float = 15.0) -> list[dict]:
    """Pull the canonical CISA KEV catalog feed."""
    return kev_feeds.BY_SLUG[kev_feeds.CISA].fetch(timeout)


def fetch_epss(timeout: float = 15.0, cve_ids: list[str] | None = None) -> list[dict]:
    """Pull EPSS scores from the FIRST public API (no key supported).

    Without ids this returns the highest-scoring 500 advisories in the world,
    which is not the same thing as "the ones in this inventory": a CVE published
    last week scores low and would silently stay `unknown`. With ids it asks for
    exactly what the catalogue holds, so an unknown score means the feed has none.
    """
    entries: list[dict] = []
    if cve_ids:
        for start in range(0, len(cve_ids), 80):
            chunk = cve_ids[start:start + 80]
            url = f"{EPSS_URL}?cve={','.join(chunk)}"
            with urllib.request.urlopen(url, timeout=timeout) as response:
                payload = json.load(response)
            entries.extend(payload.get("data", []) or [])
    else:
        url = f"{EPSS_URL}?limit=500"
        with urllib.request.urlopen(url, timeout=timeout) as response:
            payload = json.load(response)
        entries = payload.get("data", []) or []
    rows = []
    for entry in entries:
        rows.append({
            "cve_id": entry.get("cve"),
            "epss": f"{float(entry.get('epss', 0)):.6f}",
            "percentile": f"{float(entry.get('percentile', 0)):.6f}",
        })
    return rows


def _reconcile_fingerprints(session, org, project=None):
    """Re-key vulnerability findings to the CVE when one is (now) known.
    Grouped pass: findings that would collide on the canonical fingerprint
    collapse onto the oldest row (its history absorbs the rest). Idempotent."""
    candidates = (session.query(models.Finding)
                  .filter_by(org_id=org.id, kind="vulnerability")).all()
    if project is not None:
        candidates = [row for row in candidates if row.project_id == project.id]

    grouped: dict[tuple, list] = {}
    for finding in candidates:
        if finding.vulnerability_id is None or finding.component_id is None:
            continue
        advisory = session.get(models.Vulnerability, finding.vulnerability_id)
        component = session.get(models.Component, finding.component_id)
        if advisory is None or component is None:
            continue
        canonical_key = advisory.cve_id or advisory.source_id
        canonical = vulnerability_fingerprint(
            org.id, finding.project_id, component.identity_key, canonical_key)
        if canonical == finding.fingerprint:
            continue
        grouped.setdefault((finding.project_id, canonical, canonical_key), []) \
               .append((finding, advisory))

    changed = 0
    for (_project_id, canonical, canonical_key), members in grouped.items():
        members.sort(key=lambda pair: pair[0].first_seen_at or models.utcnow())
        keeper, keeper_advisory = members[0]
        keeper.fingerprint = canonical
        keeper.vulnerability_id = keeper_advisory.id
        changed += 1
        for extra, _advisory in members[1:]:
            keeper.last_seen_at = max(keeper.last_seen_at, extra.last_seen_at)
            keeper.last_seen_version_id = extra.last_seen_version_id or keeper.last_seen_version_id
            session.delete(extra)
            changed += 1
    return changed


#: Words that match everything and therefore mean nothing when a KEV product is
#: compared to a purl. Matching is deliberately word-level (`\bnode\b`, never
#: `node-`), because `node-tar` is not Node.js and a false "you are exposed" costs
#: more than a missed row the reader can find by product name.
_TOKEN_STOPWORDS = {
    "the", "and", "for", "inc", "ltd", "corp", "llc", "project", "software",
    "server", "serverless", "client", "http", "https", "api", "web", "core",
    "common", "runtime", "library", "framework", "appliance", "platform",
    "system", "systems", "service", "services", "manager", "console", "portal",
    "gateway", "proxy", "agent", "cloud", "enterprise", "plugin", "module",
    # Words a product name shares with a hundred unrelated purls. Matching on these
    # is how "Internet Key Exchange (IKE) Service Extensions" came back as
    # `typing-extensions`: a hint that fires on everything is noise, not a hint.
    "extensions", "extension", "exchange", "multiple", "products", "product",
    "native", "community", "suite", "tools", "internet", "authentication",
    "improper", "access", "control", "request", "response", "vulnerability",
    "unchecked", "return", "value", "single", "factor", "predictable",
    "missing", "injection", "bypass", "traversal", "remote", "local",
}

#: A token shared by more than this many estate entries says nothing about which one
#: to open, so it is dropped instead of matching half the inventory.
_MAX_TOKEN_FANOUT = 6


def _tokens(text: str | None, minimum: int = 4) -> set[str]:
    found = set()
    for token in (text or "").lower().replace("_", " ").replace("/", " ").split():
        token = "".join(ch for ch in token if ch.isalnum())
        if len(token) >= minimum and token not in _TOKEN_STOPWORDS:
            found.add(token)
    return found


def _estate_terms(session: Session, org: models.Organization
                  ) -> tuple[dict[str, list[dict]], dict[str, list[dict]]]:
    """`({token: [{kind, id, label}]}, {cve: [{kind, id, label}]})` for this org.

    Two kinds of evidence, and they are not the same claim:

    * **by CVE** — a finding already exists for that advisory. Exact.
    * **by product** — the advisory's product words appear in a purl or a technology
      observation. A hint to look, never a verdict: KEV says "Google Brotli" while the
      estate holds `pkg:docker/node@22-alpine`, so the exact join is what catches it.
    """
    index: dict[str, list[dict]] = {}
    by_cve: dict[str, list[dict]] = {}

    def add(kind: str, row_id: str | None, label: str | None, text: str | None):
        for token in _tokens(text):
            bucket = index.setdefault(token, [])
            entry = {"kind": kind, "id": row_id, "label": (label or "")[:200]}
            if entry not in bucket:
                bucket.append(entry)

    for row in session.query(models.Component).filter_by(org_id=org.id).all():
        add("component", row.id, row.purl or row.name, f"{row.purl or ''} {row.name or ''}")
    for row in (session.query(models.Observation)
                .filter_by(org_id=org.id, kind="technology").all()):
        value = row.value if isinstance(row.value, dict) else {}
        add("observation", row.id, row.subject,
            f"{row.subject or ''} {value.get('label') or ''} "
            f"{value.get('product') or ''} {value.get('vendor') or ''}")

    findings = (session.query(models.Finding.id, models.Vulnerability.cve_id,
                              models.Component.purl, models.Component.name)
                .join(models.Vulnerability,
                      models.Vulnerability.id == models.Finding.vulnerability_id)
                .outerjoin(models.Component,
                           models.Component.id == models.Finding.component_id)
                .filter(models.Finding.org_id == org.id,
                        models.Vulnerability.cve_id.isnot(None))
                .all())
    for finding_id, cve_id, purl, name in findings:
        bucket = by_cve.setdefault(cve_id, [])
        entry = {"kind": "finding", "id": finding_id,
                 "label": (purl or name or "component not recorded")[:200]}
        if entry not in bucket:
            bucket.append(entry)
    return index, by_cve


def _matches_for(row: models.KevEntry, index: dict[str, list[dict]],
                 by_cve: dict[str, list[dict]]) -> list[dict]:
    found: list[dict] = []
    seen: set[tuple] = set()
    candidates = list(by_cve.get(row.cve_id, []))
    # The product is the claim; the vulnerability name is prose ("Unchecked Return
    # Value Vulnerability") and matching on it produced false positives. Five letters
    # is the floor: `node` alone matched "OpenView Network *Node* Manager", and a hint
    # that fires on a common English word is worse than no hint.
    for token in _tokens(f"{row.product or ''} {row.vendor or ''}", minimum=5):
        bucket = index.get(token, [])
        if len(bucket) > _MAX_TOKEN_FANOUT:
            continue
        candidates.extend(bucket)
    for entry in candidates:
        key = (entry["kind"], entry["id"])
        if key in seen:
            continue
        seen.add(key)
        found.append(entry)
    return found[:6]


def _iso_date(value: str | None, field: str) -> datetime.date | None:
    if not value:
        return None
    try:
        return datetime.date.fromisoformat(value)
    except ValueError:
        raise HTTPException(422, f"{field} must be an ISO date (YYYY-MM-DD)") from None


def _age_hours(value: datetime.datetime | None) -> float | None:
    """Hours since a feed row was fetched. SQLite hands back naive datetimes."""
    if value is None:
        return None
    aware = value if value.tzinfo else value.replace(tzinfo=datetime.timezone.utc)
    return round((models.utcnow() - aware).total_seconds() / 3600, 1)


def _kev_text_match(row: models.KevEntry, needle: str) -> bool:
    return (needle in (row.cve_id or "").lower()
            or needle in (row.name or row.title or "").lower()
            or needle in (row.product or "").lower()
            or needle in (row.vendor or "").lower()
            or needle in (row.description or "").lower())


def _estate_findings(session: Session, org: models.Organization, cve_id: str) -> dict:
    """What this estate already holds for one CVE: counts and the components behind."""
    rows = (session.query(models.Finding.id, models.Finding.status,
                          models.Component.purl, models.Component.name)
            .join(models.Vulnerability,
                  models.Vulnerability.id == models.Finding.vulnerability_id)
            .outerjoin(models.Component,
                       models.Component.id == models.Finding.component_id)
            .filter(models.Finding.org_id == org.id,
                    models.Vulnerability.cve_id == cve_id)
            .all())
    open_rows = [row for row in rows if row[1] in {"open", "acknowledged"}]
    components = sorted({row[2] or row[3] for row in rows if (row[2] or row[3])})
    return {"findings": len(rows), "open": len(open_rows),
            "components": components[:10]}


@router.get("/intel/advisory")
def advisory_resolve(q: str = Query(..., min_length=2,
                                    description="nickname, CVE id, or product text"),
                     org: models.Organization = Depends(auth.require_org),
                     session: Session = Depends(get_session)):
    """Resolve what the operator called it into a CVE, then say what the estate holds.

    `node2shell`, `Node 2 Shell`, `CVE-2026-111497` and `brotli` all reach the same
    advisory by three different paths, in this order: the curated nickname table, the
    literal CVE, and a text match over the mirror. The answer always names which path
    worked, because "resolved by nickname" and "guessed from a product word" are not
    the same confidence.
    """
    term = q.strip()
    cve = advisory_names.resolve(term)
    how = "alias" if cve and not advisory_names.CVE_RE.match(term) else ("cve" if cve else None)
    candidates: list[models.KevEntry] = []

    if cve:
        row = session.get(models.KevEntry, cve)
        rows = [row] if row else []
    else:
        needle = term.lower()
        rows = [row for row in session.query(models.KevEntry).all()
                if _kev_text_match(row, needle)]
        how = "text" if rows else None
        # A text match is only a resolution when it is unambiguous.
        if len(rows) == 1:
            cve = rows[0].cve_id
        else:
            candidates = rows[:5]

    index, by_cve = _estate_terms(session, org)
    epss = {row.cve_id: row for row in session.query(models.EpssScore).all()}
    today = datetime.date.today()
    kev = (_kev_row(rows[0], epss.get(rows[0].cve_id),
                    _matches_for(rows[0], index, by_cve), today)
           if rows else None)
    estate = _estate_findings(session, org, cve) if cve else {
        "findings": 0, "open": 0, "components": []}

    if not rows and not cve:
        why = (f"no nickname maps to «{term}» and the KEV mirror has no row matching "
               "it; that is unknown, not 'not affected'")
    elif len(rows) > 1 and not cve:
        why = (f"«{term}» matches {len(rows)} advisories; pick one by CVE id — the "
               "estate cannot be judged against an ambiguous name")
    else:
        why = None

    return {"data": {
        "query": term,
        "resolved": bool(cve),
        "how": how,
        "cve_id": cve,
        "kev": kev,
        "estate": estate,
        "candidates": [
            {"cve_id": row.cve_id, "name": row.name or row.title,
             "vendor": row.vendor, "product": row.product,
             "date_added": row.date_added}
            for row in candidates
        ],
        "why": why,
    }}


def _kev_row(row: models.KevEntry, epss: models.EpssScore | None,
             matches: list[dict], today: datetime.date) -> dict:
    # A feed row is data, not input: a malformed due date must not kill the list.
    try:
        due = datetime.date.fromisoformat(row.due_date) if row.due_date else None
    except ValueError:
        due = None
    return {
        "cve_id": row.cve_id,
        "name": row.name or row.title,
        "vendor": row.vendor,
        "product": row.product,
        "description": row.description,
        "required_action": row.required_action,
        "ransomware": (row.ransomware or "").lower() == "known",
        "cwes": row.cwes,
        "date_added": row.date_added,
        "due_date": row.due_date,
        "days_to_due": (due - today).days if due else None,
        "epss": epss.epss if epss else None,
        "epss_percentile": epss.percentile if epss else None,
        # Provenance, in authority order. The screen shows it as "who says so":
        # one catalogue listing a CVE and three agreeing are different evidence.
        "sources": _row_sources(row),
        "exploitation_type": row.exploitation_type,
        "euvd_id": row.euvd_id,
        # Two kinds of evidence, kept apart: CISA's notes and the report the EU
        # list links as proof that the exploitation happened.
        "evidence": row.notes,
        "eu_evidence": row.eu_evidence,
        "matched": bool(matches),
        "matches": matches,
    }


def _row_sources(row: models.KevEntry) -> list[str]:
    """The catalogues that list this CVE, tolerant of rows imported before they did."""
    slugs = [item for item in (row.sources or "").split(",") if item.strip()]
    if not slugs and row.source:
        slugs = [row.source]
    return slugs


@router.get("/intel/kev")
def kev_catalog(since: str | None = Query(default=None,
                                          description="added on or after (YYYY-MM-DD)"),
                until: str | None = Query(default=None,
                                          description="added on or before (YYYY-MM-DD)"),
                q: str | None = Query(default=None),
                product: str | None = Query(default=None),
                vendor: str | None = Query(default=None),
                source: str | None = Query(default=None,
                                           description="only rows listed by this catalogue"),
                due_before: str | None = Query(default=None),
                ransomware: bool = Query(default=False),
                matched: bool = Query(default=False,
                                      description="only rows that touch this estate"),
                sort: str = Query(default="date_added",
                                  pattern="^(date_added|due_date|epss|cve)$"),
                limit: int = Query(default=50, ge=1, le=200),
                offset: int = Query(default=0, ge=0),
                org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    """The world's catalogue, not this estate's findings.

    Answers "what came out this week, and does it touch anything I run" without
    needing a matching finding to exist first. `matched` is a hint built by comparing
    the advisory's product words against the purls and technologies this org actually
    holds — it says *look here*, never "you are affected".

    `source` narrows to one publisher (CISA, EU, VulnCheck…): the merged row carries
    every catalogue that lists the CVE, and a reader who only trusts one of them is
    entitled to say so.
    """
    since_date = _iso_date(since, "since")
    until_date = _iso_date(until, "until")
    due_date = _iso_date(due_before, "due_before")
    today = datetime.date.today()

    rows = session.query(models.KevEntry).all()
    feed_rows = len(rows)
    fetched_at = max((row.fetched_at for row in rows if row.fetched_at), default=None)
    if until_date:
        rows = [row for row in rows if (row.date_added or "") <= until_date.isoformat()]
    if since_date:
        rows = [row for row in rows if (row.date_added or "") >= since_date.isoformat()]
    if due_date:
        rows = [row for row in rows
                if row.due_date and row.due_date <= due_date.isoformat()]
    if ransomware:
        rows = [row for row in rows if (row.ransomware or "").lower() == "known"]
    if product:
        needle = product.strip().lower()
        rows = [row for row in rows if needle in (row.product or "").lower()]
    if vendor:
        needle = vendor.strip().lower()
        rows = [row for row in rows if needle in (row.vendor or "").lower()]
    if source:
        needle = source.strip().lower()
        rows = [row for row in rows if needle in _row_sources(row)]
    if q:
        needle = q.strip().lower()
        rows = [row for row in rows if _kev_text_match(row, needle)]

    index, by_cve = _estate_terms(session, org)
    epss = {row.cve_id: row for row in session.query(models.EpssScore).all()}
    data = [_kev_row(row, epss.get(row.cve_id), _matches_for(row, index, by_cve), today)
            for row in rows]
    matched_rows = [row for row in data if row["matched"]]
    if matched:
        data = matched_rows

    def due_key(row):
        return (row["due_date"] is None, row["due_date"] or "")

    if sort == "due_date":
        data.sort(key=due_key)
    elif sort == "epss":
        data.sort(key=lambda row: float(row["epss"] or 0), reverse=True)
    elif sort == "cve":
        data.sort(key=lambda row: row["cve_id"])
    else:
        data.sort(key=lambda row: (row["date_added"] or "", row["cve_id"]),
                  reverse=True)

    week = today + datetime.timedelta(days=7)
    return {
        "data": data[offset:offset + limit],
        "total": len(data),
        "limit": limit,
        "offset": offset,
        "counts": {
            "feed_rows": feed_rows,
            "matched": len(matched_rows),
            "new_since": len(data) if since_date else None,
            "due_within_7d": sum(1 for row in data
                                 if row["due_date"] and row["due_date"] <= week.isoformat()),
            "ransomware": sum(1 for row in data if row["ransomware"]),
        },
        "coverage": {
            "feed": "connected" if feed_rows else "never synced",
            "rows": feed_rows,
            "fetched_at": fetched_at.isoformat() if fetched_at else None,
            "synced_age_hours": _age_hours(fetched_at),
            # One line per catalogue: a merged total cannot say which publisher is
            # stale, and "never synced" must stay distinguishable from "broke".
            "sources": kev_feeds.coverage(session),
        },
    }


@router.get("/intel/kev/{cve_id}")
def kev_for(cve_id: str, org: models.Organization = Depends(auth.require_org),
            session: Session = Depends(get_session)):
    row = session.get(models.KevEntry, cve_id)
    if row is None:
        return {"data": None, "known_exploited": False}
    return {"data": {"cve_id": row.cve_id, "title": row.title or row.name,
                     "name": row.name, "vendor": row.vendor,
                     "product": row.product, "description": row.description,
                     "required_action": row.required_action,
                     "ransomware": row.ransomware,
                     "date_added": row.date_added, "due_date": row.due_date,
                     "sources": _row_sources(row),
                     "exploitation_type": row.exploitation_type,
                     "euvd_id": row.euvd_id,
                     "evidence": row.notes,
                     "eu_evidence": row.eu_evidence},
            "known_exploited": True}


@router.get("/intel/epss/{cve_id}")
def epss_for(cve_id: str, org: models.Organization = Depends(auth.require_org),
             session: Session = Depends(get_session)):
    row = session.get(models.EpssScore, cve_id)
    if row is None:
        return {"data": None, "epss": None}
    return {"data": {"cve_id": row.cve_id, "epss": row.epss,
                     "percentile": row.percentile}}


class SyncResult(BaseModel):
    kev_fetched: int = 0
    epss_fetched: int = 0


@router.post("/intel/sync")
def sync_feeds(org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    """Refresh the local KEV/EPSS tables from every catalogue we mirror.

    KEV is merged from more than one publisher (see `kev_feeds`), so one feed being
    down is a reported fact and not a failed sync. Only a total outage — every
    catalogue refusing — is a 502, and then the detail says which one said what.
    """
    now = models.utcnow()
    result = kev_feeds.sync(session, now=now)
    sources = result["sources"]
    if sources and all(not item["ok"] for item in sources):
        session.commit()  # keep the per-source error, or the next sync looks clean
        detail = "; ".join(f"{item['source']}: {item.get('error') or 'failed'}"
                          for item in sources)
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"KEV sync failed: {detail}")

    epss_n = 0
    held = sorted({row.cve_id for row in session.query(models.Vulnerability).all()
                   if row.cve_id})
    try:
        rows = fetch_epss(cve_ids=held) if held else fetch_epss()
    except Exception as error:  # noqa: BLE001
        raise HTTPException(status.HTTP_502_BAD_GATEWAY,
                            f"EPSS sync failed: {type(error).__name__}") from None
    for row in rows:
        session.merge(models.EpssScore(**row, fetched_at=now))
        epss_n += 1
    _audit_log(session, org.id, "platform", "intel.synced", None, None,
               f"kev={result['rows']} epss={epss_n} sources="
               + ",".join(f"{item['source']}={item['rows']}" for item in sources))
    session.commit()
    return {"data": {"kev_fetched": result["rows"], "epss_fetched": epss_n,
                     "sources": sources}}


class VexIn(BaseModel):
    finding_id: str
    status: str
    statement: str = Field(min_length=4, max_length=8192)
    author: str | None = Field(default=None, max_length=255)


class VexOut(BaseModel):
    id: str
    status: str


@router.get("/vex")
def list_vex(org: models.Organization = Depends(auth.require_org),
             session: Session = Depends(get_session)):
    rows = (session.query(models.VexStatement)
            .filter_by(org_id=org.id)
            .order_by(models.VexStatement.created_at.desc()).all())
    return {"data": [{"id": r.id, "finding_id": r.finding_id, "status": r.status,
                      "statement": r.statement, "author": r.author} for r in rows],
            "total": len(rows)}


@router.post("/vex")
def add_vex(payload: VexIn = None,
            org: models.Organization = Depends(auth.require_org),
            session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.status not in VEX_STATUSES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"status must be one of {sorted(VEX_STATUSES)}")
    finding = session.get(models.Finding, payload.finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    statement = models.VexStatement(
        org_id=org.id, finding_id=finding.id, status=payload.status,
        statement=payload.statement, author=payload.author,
        created_at=models.utcnow(), updated_at=models.utcnow())
    session.add(statement)
    session.flush()
    _audit_log(session, org.id, payload.author or "system", "vex.added",
               "vex_statement", statement.id, f"{finding.id[:12]} -> {payload.status}")
    session.commit()
    return {"data": {"id": statement.id, "status": statement.status}}


@router.post("/intelligence/reconcile")
def reconcile(org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session)):
    """Collapse advisory-split findings onto CVE-anchored fingerprints."""
    changed = _reconcile_fingerprints(session, org)
    session.commit()
    return {"data": {"reconciled": changed}}

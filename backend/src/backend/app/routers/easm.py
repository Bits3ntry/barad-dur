"""B4 endpoints: externally observable assets, crt.sh subdomain sweep."""
import datetime
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from email.utils import parsedate_to_datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, models
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1", tags=["easm"])

CRTSH_CTLOG = "https://crt.sh/?q=%25.{domain}&output=json"


def _parse_cert_date(value) -> str | None:
    """TLS dates arrive in RFC-822 form ("Dec 20 14:00:30 2026 GMT")."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return parsedate_to_datetime(value).isoformat()
    except (TypeError, ValueError):
        return None


def _latest_observation(session: Session, asset: models.Asset) -> dict | None:
    """Newest snapshot, flattened enough for a table: addresses and certificate."""
    snapshot = (session.query(models.AssetSnapshot)
                .filter_by(asset_id=asset.id)
                .order_by(models.AssetSnapshot.observed_at.desc()).first())
    if snapshot is None:
        return None
    try:
        data = json.loads(snapshot.data)
    except (TypeError, ValueError):
        return {"observed_at": snapshot.observed_at.isoformat(), "error": "unreadable"}
    dns = data.get("dns") or {}
    tls = data.get("tls") or {}
    not_after = _parse_cert_date(tls.get("not_after"))
    days_left = None
    if not_after:
        days_left = (datetime.datetime.fromisoformat(not_after)
                     - datetime.datetime.now(datetime.timezone.utc)).days
    return {
        "observed_at": snapshot.observed_at.isoformat(),
        "source": snapshot.source,
        "ipv4": dns.get("ipv4") or [],
        "ipv6": dns.get("ipv6") or [],
        "certificate": {
            "subject": (tls.get("subject") or {}).get("commonName"),
            "issuer": (tls.get("issuer") or {}).get("organizationName"),
            "not_after": not_after,
            "days_left": days_left,
            "tls_version": tls.get("tls_version"),
        } if tls else None,
        # One row per product. httpx and nmap both fingerprint the same host, so
        # the list arrived with "haproxy" twice (one with a version, one without)
        # and the overview counted six technologies on a host that runs four.
        "tech": _dedupe_tech(data.get("tech") or []),
    }


def _observation_value(observation: models.Observation) -> dict:
    """The row's payload as a dict.

    `Observation.value` is a JSON column, so SQLAlchemy already hands back a
    dict. It used to be passed through `json.loads`, which raised on a dict and
    the `except` swallowed it — every technology row the scanners found was
    silently dropped and the panel read "nothing fingerprinted yet".
    """
    value = observation.value
    if isinstance(value, dict):
        return value
    if isinstance(value, (str, bytes)):
        try:
            parsed = json.loads(value or "{}")
        except (TypeError, ValueError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


# What an open port is for, in the words a reader needs. The service name is
# what the daemon announced; the purpose is the standard role of that service,
# not a guess about what this deployment does with it.
SERVICE_PURPOSE = {
    "ftp": "file transfer", "ftps": "file transfer over TLS",
    "ssh": "remote shell", "telnet": "remote shell (plaintext)",
    "smtp": "mail transfer", "submission": "mail submission (authenticated)",
    "smtps": "mail submission over TLS",
    "pop3": "mailbox, POP3", "pop3s": "mailbox, POP3 over TLS",
    "imap": "mailbox, IMAP", "imaps": "mailbox, IMAP over TLS",
    "domain": "DNS", "http": "web", "https": "web over TLS",
    "http-alt": "web (alternate port)", "http-proxy": "web proxy",
    "mysql": "database, MySQL", "postgresql": "database, PostgreSQL",
    "ms-sql-s": "database, SQL Server", "redis": "cache, Redis",
    "mongodb": "database, MongoDB", "elasticsearch": "search, Elasticsearch",
    "ldap": "directory, LDAP", "ldaps": "directory, LDAP over TLS",
    "rdp": "remote desktop", "vnc": "remote desktop, VNC",
    "smb": "file sharing, SMB", "nfs": "file sharing, NFS",
    "ntp": "time", "snmp": "monitoring, SNMP",
}

PORT_PURPOSE = {
    21: "file transfer", 22: "remote shell", 23: "remote shell (plaintext)",
    25: "mail transfer", 53: "DNS", 80: "web", 110: "mailbox, POP3",
    143: "mailbox, IMAP", 443: "web over TLS", 445: "file sharing, SMB",
    465: "mail submission over TLS", 587: "mail submission (authenticated)",
    993: "mailbox, IMAP over TLS", 995: "mailbox, POP3 over TLS",
    3306: "database, MySQL", 3389: "remote desktop", 5432: "database, PostgreSQL",
    6379: "cache, Redis", 8080: "web (alternate port)", 8443: "web over TLS (alternate)",
}


def _port_rows(session: Session, asset: models.Asset) -> list[dict]:
    """One row per open port, with the banner that described it.

    The scanners disagree on purpose: naabu says a port answers, nmap says what
    answers on it. Merging them per port keeps the version nmap read and the
    fact that two tools saw the same port.
    """
    rows: dict[int, dict] = {}
    for observation in (session.query(models.Observation)
                        .filter_by(asset_id=asset.id, kind="port")
                        .order_by(models.Observation.observed_at.desc()).limit(400).all()):
        if observation.port is None:
            continue
        value = _observation_value(observation)
        row = rows.setdefault(observation.port, {
            "port": observation.port,
            "protocol": observation.protocol or "tcp",
            "state": "open", "service": None, "product": None, "version": None,
            "sources": [], "observed_at": None,
        })
        if value.get("state") == "open":
            row["state"] = "open"
        # Newest non-empty wins: the query is ordered newest first, so the first
        # tool that named the service is the closest one to the truth.
        for field in ("service", "product", "version"):
            if not row[field] and value.get(field):
                row[field] = str(value[field]).strip()
        if observation.source and observation.source not in row["sources"]:
            row["sources"].append(observation.source)
        if row["observed_at"] is None and observation.observed_at:
            row["observed_at"] = observation.observed_at.isoformat()
    for row in rows.values():
        row["purpose"] = (SERVICE_PURPOSE.get((row["service"] or "").lower())
                          or PORT_PURPOSE.get(row["port"]))
        row["sources"].sort()
    return sorted(rows.values(), key=lambda row: row["port"])


def _split_tech(label: str) -> dict:
    """`PHP:8.2.35` and `jquery/3.7.1` are the same fact written twice."""
    text = str(label or "").strip()
    for separator in (":", "/"):
        if separator in text:
            name, _, version = text.partition(separator)
            if name.strip():
                return {"name": name.strip().lower(), "version": version.strip() or None}
    return {"name": text.lower(), "version": None}


def _web_rows(session: Session, asset: models.Asset) -> list[dict]:
    """What answers on the web, per URL, with the stack behind it.

    A port says "80 is open"; this says "this is nginx serving PHP 8.2.35 with
    WordPress", which is the sentence the reader is looking for.
    """
    rows: dict[str, dict] = {}
    # httpx records a fetched page as `web_path` and the fingerprint as
    # `technology`; the stack lives on the page it was read from, so both kinds
    # are read here and only the rows that name a URL matter.
    for observation in (session.query(models.Observation)
                        .filter(models.Observation.asset_id == asset.id,
                                models.Observation.kind.in_(("web_path", "technology")))
                        .order_by(models.Observation.observed_at.desc()).limit(120).all()):
        value = _observation_value(observation)
        url = str(value.get("url") or "").strip()
        if not url:
            continue
        row = rows.setdefault(url, {"url": url, "status": None, "server": None,
                                    "title": None, "tech": [], "observed_at": None})
        for field in ("status", "server", "title"):
            if row[field] in (None, "") and value.get(field) not in (None, ""):
                row[field] = value[field]
        seen = {entry["name"] for entry in row["tech"]}
        for label in value.get("tech") or []:
            parsed = _split_tech(label)
            if parsed["name"] and parsed["name"] not in seen:
                row["tech"].append(parsed)
                seen.add(parsed["name"])
        # A tool that reads one page says so with a url: its products belong to
        # that page's stack, not only to the asset-wide list.
        for product in value.get("products") or []:
            name = str(product.get("name") or "").strip().lower()
            if not name or name in seen:
                continue
            row["tech"].append({"name": name, "version": product.get("version") or None})
            seen.add(name)
        if row["observed_at"] is None and observation.observed_at:
            row["observed_at"] = observation.observed_at.isoformat()
    for row in rows.values():
        row["tech"].sort(key=lambda entry: (entry["version"] is None, entry["name"]))
    return sorted(rows.values(), key=lambda row: row["url"])


def _technology_rows(session: Session, asset: models.Asset) -> list[dict]:
    """Products with their evidence, newest observations first.

    The chips on the old page carried a name and a slash; the table needs to say
    which tool claimed it and how sure that tool was, or a version is a guess
    presented as a fact.
    """
    rows: dict[tuple[str, str | None], dict] = {}
    for observation in (session.query(models.Observation)
                        .filter_by(asset_id=asset.id, kind="technology")
                        .order_by(models.Observation.observed_at.desc()).limit(40).all()):
        value = _observation_value(observation)
        for product in value.get("products") or []:
            name = str(product.get("name") or "").strip().lower()
            if not name:
                continue
            key = (name, product.get("version") or None)
            rows.setdefault(key, {"name": name, "version": product.get("version"),
                                  "evidence": product.get("evidence"),
                                  "confidence": product.get("confidence"),
                                  "source": observation.source,
                                  "observed_at": (observation.observed_at.isoformat()
                                                  if observation.observed_at else None)})
    return sorted(rows.values(), key=lambda row: row["name"])


def _dedupe_tech(values: list) -> list[str]:
    best: dict[str, str] = {}
    for raw in values:
        text = str(raw)
        name, _, version = text.partition("/")
        key = name.strip().lower()
        if not key:
            continue
        current = best.get(key, "")
        if not current or (version and "/" not in current):
            best[key] = text
    return [best[key] for key in sorted(best)]



def crtsh_subdomains(domain: str, timeout: float = 25.0) -> list[str]:
    """Certificate-transparency sweep for the domain (public crt.sh JSON)."""
    url = CRTSH_CTLOG.format(domain=domain)
    with urllib.request.urlopen(url, timeout=timeout) as response:
        payload = json.load(response)
    found: set[str] = set()
    for entry in payload:
        name_value = entry.get("name_value") or ""
        for name in name_value.splitlines():
            name = name.strip().lower().lstrip("*.")
            if name.endswith(domain) and name != domain:
                found.add(name)
        common_name = (entry.get("common_name") or "").strip().lower().lstrip("*.")
        if common_name.endswith(domain) and common_name != domain:
            found.add(common_name)
    return sorted(found)


def _asset_data(session: Session, asset: models.Asset, parent: dict | None = None,
                authorization_state: dict | None = None) -> dict:
    project = session.get(models.Project, asset.project_id) if asset.project_id else None
    groups = (session.query(models.InventoryGroup)
              .join(models.InventoryGroupMember,
                    models.InventoryGroupMember.group_id == models.InventoryGroup.id)
              .filter(models.InventoryGroupMember.asset_id == asset.id,
                      models.InventoryGroupMember.removed_at.is_(None)).all())
    return {"id": asset.id, "type": asset.type, "value": asset.value,
            "source": asset.source, "detail": asset.detail,
            "project": project.slug if project else None,
            "project_name": project.name if project else None,
            "owner": asset.owner,
            "classification_status": asset.classification_status,
            "notes": asset.notes,
            "archived_at": asset.archived_at.isoformat() if asset.archived_at else None,
            "groups": [{"id": g.id, "name": g.name} for g in groups],
            "discovered_at": asset.discovered_at.isoformat(),
            "last_seen_at": asset.last_seen_at.isoformat(),
            "parent": parent,
            "authorization": authorization_state or {},
            "latest": _latest_observation(session, asset)}


def _ancestor_project(session: Session, org_id: str, asset: models.Asset):
    """The project of the nearest ancestor that has one, for an asset without."""
    if asset.type != "domain" or "." not in asset.value:
        return None
    labels = asset.value.lower().split(".")
    for cut in range(1, len(labels) - 1):
        candidate = ".".join(labels[cut:])
        parent = (session.query(models.Asset)
                  .filter_by(org_id=org_id, type="domain", value=candidate)
                  .one_or_none())
        if parent is not None and parent.project_id:
            return parent.project_id
    return None


def _cascade_project(session: Session, org_id: str, parent: models.Asset,
                     previous_id: str | None = None) -> int:
    """Every descendant that has no project of its own follows the parent's.

    `*.dominio.com` assigned to a project must not leave 200 subdomains to be
    assigned one by one. The match is by label suffix (`"." + parent`), so
    `notdominio.com` is not a child of `dominio.com`, and a child explicitly put in
    another project is left alone — an override is a decision, not an oversight.
    Rows that carried the **previous** project follow the change; rows with a
    different one do not.
    """
    if parent.type != "domain" or not parent.project_id:
        return 0
    suffix = "." + parent.value.lower()
    inherited = 0
    rows = (session.query(models.Asset)
            .filter_by(org_id=org_id, type="domain").all())
    for row in rows:
        if row.id == parent.id or not row.value.lower().endswith(suffix):
            continue
        if row.project_id in (None, previous_id):
            row.project_id = parent.project_id
            inherited += 1
    return inherited


def _domain_parents(session: Session, org_id: str) -> dict[str, dict]:
    """Longest existing ancestor per domain: `dev.api.x.com` hangs from
    `api.x.com` when that row exists, else from `x.com`, else from nothing.

    Derived, not stored: the tree is a reading of the names the organization
    actually declared, so a new subdomain appears under its parent the moment it
    is created and no edge table has to be kept in step with it.
    """
    rows = (session.query(models.Asset)
            .filter_by(org_id=org_id, type="domain")
            .filter(models.Asset.archived_at.is_(None)).all())
    by_value = {row.value.lower(): row for row in rows}
    parents: dict[str, dict] = {}
    for value, row in by_value.items():
        labels = value.split(".")
        for cut in range(1, len(labels) - 1):
            candidate = ".".join(labels[cut:])
            parent = by_value.get(candidate)
            if parent is not None and parent.id != row.id:
                parents[row.id] = {"id": parent.id, "value": parent.value,
                                   "depth": cut}
                break
    return parents


def _authorization_states(session: Session, org_id: str,
                          asset_ids: set[str]) -> dict[str, dict]:
    """Pending request and highest covered level per asset, in two queries."""
    from backend.app import authorization

    pending: dict[str, str] = {}
    if asset_ids:
        for row in (session.query(models.ScanGrant)
                    .filter(models.ScanGrant.org_id == org_id,
                            models.ScanGrant.status == "requested",
                            models.ScanGrant.asset_id.in_(asset_ids)).all()):
            pending[row.asset_id] = row.id
    active = (session.query(models.ScanGrant)
              .filter_by(org_id=org_id, status="active").all())
    now = models.utcnow()
    states: dict[str, dict] = {}
    for asset_id in asset_ids:
        asset = session.get(models.Asset, asset_id)
        if asset is None:
            continue
        target = authorization.target_for_asset(asset)
        covered = None
        for level in reversed(authorization.SCAN_LEVEL_ORDER):
            caps = set(authorization.capabilities_for_level(level))
            for grant in active:
                if not caps <= authorization.authorization_capabilities(grant):
                    continue
                valid_until = grant.valid_until
                if valid_until is not None and valid_until.tzinfo is None:
                    valid_until = valid_until.replace(tzinfo=datetime.timezone.utc)
                if valid_until is not None and valid_until < now:
                    continue
                if authorization._target_allowed(session, grant, target["type"],
                                                 target["value"]):
                    covered = level
                    break
            if covered:
                break
        # The most confusing state in the inventory: an asset with no coverage
        # sitting next to an active grant on the same name. It is not a bug — a
        # wildcard does not cover its apex — but saying nothing made it look like
        # one, so the reason travels with the state.
        zone_cover = None
        if not covered and asset.type == "domain":
            zone = authorization.zone_of(asset.value)
            if str(asset.value).lower() == zone:
                wanted = f"*.{zone}"
                for grant in active:
                    if any(str(t.target_value).lower() == wanted for t in grant.targets):
                        zone_cover = {"target": wanted, "level": grant.level,
                                      "grant_id": grant.id}
                        break
        states[asset_id] = {"level": covered, "covered": bool(covered),
                            "pending_request_id": pending.get(asset_id),
                            "zone_cover": zone_cover}
    return states


@router.get("/assets")
def list_assets(type: str | None = None,
                project: str | None = None,
                group_id: str | None = None,
                owner: str | None = None,
                classification: str | None = None,
                q: str | None = None,
                include_archived: bool = False,
                limit: int = Query(default=100, ge=1, le=500),
                offset: int = Query(default=0, ge=0),
                org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    """Inventory paging/filtering. `total` counts the filtered set, not the page."""
    query = session.query(models.Asset).filter_by(org_id=org.id)
    if type is not None:
        query = query.filter_by(type=type)
    if not include_archived:
        query = query.filter(models.Asset.archived_at.is_(None))
    if owner is not None:
        query = query.filter(models.Asset.owner == owner)
    if classification is not None:
        query = query.filter(models.Asset.classification_status == classification)
    if project is not None:
        project_row = (session.query(models.Project)
                       .filter_by(org_id=org.id, slug=project).one_or_none())
        if project_row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
        query = query.filter(models.Asset.project_id == project_row.id)
    if group_id is not None:
        query = (query.join(models.InventoryGroupMember,
                            models.InventoryGroupMember.asset_id == models.Asset.id)
                 .filter(models.InventoryGroupMember.group_id == group_id,
                         models.InventoryGroupMember.removed_at.is_(None)))
    if q:
        needle = f"%{q.strip()}%"
        query = query.filter(models.Asset.value.ilike(needle))
    total = query.count()
    rows = (query.order_by(models.Asset.last_seen_at.desc())
            .offset(offset).limit(limit).all())
    parents = _domain_parents(session, org.id)
    states = _authorization_states(session, org.id, {row.id for row in rows})
    return {"data": [_asset_data(session, r, parents.get(r.id), states.get(r.id))
                     for r in rows],
            "total": total, "limit": limit, "offset": offset}


@router.get("/assets/needs-attention")
def needs_attention(limit: int = Query(default=100, ge=1, le=500),
                    org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    """Computed queue: each row says what is missing and which action fixes it.

    Every reason is a rule that is actually implemented here; "not observed" is
    reported as a coverage gap, never as "does not exist".
    """
    rows = (session.query(models.Asset)
            .filter_by(org_id=org.id)
            .filter(models.Asset.archived_at.is_(None))
            .order_by(models.Asset.last_seen_at.asc()).all())
    items = []
    now = models.utcnow()
    for asset in rows:
        reasons = []
        if not asset.owner:
            reasons.append({"code": "no_owner", "what": "no accountable owner",
                            "action": "assign an owner"})
        if asset.project_id is None:
            reasons.append({"code": "no_project", "what": "not attached to a project",
                            "action": "link it to a project or mark it external"})
        if asset.classification_status in {"unclassified", "pending"}:
            reasons.append({"code": "ownership_unconfirmed",
                            "what": f"classification is {asset.classification_status}",
                            "action": "confirm ownership, mark external, or discard"})
        last = asset.last_seen_at
        if last is not None and last.tzinfo is None:
            last = last.replace(tzinfo=datetime.timezone.utc)
        if last is None or (now - last).days >= 30:
            reasons.append({"code": "stale", "what": "no observation in 30+ days",
                            "action": "re-collect, or record that it is retired"})
        groups = (session.query(models.InventoryGroupMember)
                  .filter_by(asset_id=asset.id, removed_at=None).count())
        deployments = (session.query(models.AssetLink)
                       .filter_by(asset_id=asset.id, entity_type="deployment",
                                  removed_at=None).count())
        if deployments == 0:
            reasons.append({"code": "no_deployment",
                            "what": "no deployment relation recorded",
                            "action": "link it to the deployment that serves it"})
        if not reasons:
            continue
        items.append({"asset": _asset_data(session, asset), "groups": groups,
                      "reasons": reasons,
                      "observation": "observed" if last else "never observed"})
    items.sort(key=lambda row: (-len(row["reasons"]), row["asset"]["value"]))
    return {"data": items[:limit], "total": len(items)}


@router.get("/assets/{asset_id}")
def get_asset(asset_id: str,
              org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session)):
    """Everything the row's "more data" panel owes the reader, in one call.

    Facts keep their observation: a certificate expiry without the moment it was
    read is a rumour, so the panel gets the snapshot metadata alongside.
    """
    asset = session.get(models.Asset, asset_id)
    if asset is None or asset.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
    parents = _domain_parents(session, org.id)
    states = _authorization_states(session, org.id, {asset.id})
    links = (session.query(models.AssetLink)
             .filter_by(org_id=org.id, asset_id=asset.id)
             .filter(models.AssetLink.removed_at.is_(None)).all())
    context = []
    for link in links:
        entry = {"link_id": link.id, "kind": link.entity_type,
                 "relation": link.relation, "id": link.entity_id}
        if link.entity_type == "deployment":
            deployment = session.get(models.Deployment, link.entity_id)
            if deployment is not None:
                component = (session.get(models.ApplicationComponent,
                                         deployment.application_component_id)
                             if deployment.application_component_id else None)
                project = (session.get(models.Project, component.project_id)
                           if component is not None else None)
                entry.update({"name": deployment.name,
                              "environment": deployment.environment,
                              "version_label": deployment.version_label,
                              "project": project.slug if project else None})
        elif link.entity_type == "application_component":
            component = session.get(models.ApplicationComponent, link.entity_id)
            if component is not None:
                project = session.get(models.Project, component.project_id)
                entry.update({"name": component.name,
                              "project": project.slug if project else None})
        elif link.entity_type == "project":
            project = session.get(models.Project, link.entity_id)
            entry.update({"name": project.name if project else link.entity_id,
                          "project": project.slug if project else None})
        context.append(entry)
    snapshots = (session.query(models.AssetSnapshot)
                 .filter_by(org_id=org.id, asset_id=asset.id)
                 .order_by(models.AssetSnapshot.observed_at.desc()).all())
    latest = _latest_observation(session, asset)
    grants = (session.query(models.ScanGrant)
              .filter(models.ScanGrant.org_id == org.id,
                      models.ScanGrant.asset_id == asset.id)
              .order_by(models.ScanGrant.created_at.desc()).all())
    data = _asset_data(session, asset, parents.get(asset.id), states.get(asset.id))
    # The page draws a relation graph; children are the edges it cannot guess.
    children = [{"id": row.id, "value": row.value}
                for row in (session.query(models.Asset)
                            .filter_by(org_id=org.id, type="domain")
                            .filter(models.Asset.archived_at.is_(None)).all())
                if (parents.get(row.id) or {}).get("id") == asset.id][:50]
    data.update({
        "children": children,
        "technologies": _technology_rows(session, asset),
        "ports": _port_rows(session, asset),
        "web": _web_rows(session, asset),
        "context": context,
        "observations": len(snapshots),
        "latest_snapshot": (json.loads(snapshots[0].data)
                            if snapshots and snapshots[0].data else None),
        "latest_source": snapshots[0].source if snapshots else None,
        "certificate_error": ((latest or {}).get("certificate") or {}).get("error")
        or (((json.loads(snapshots[0].data) if snapshots and snapshots[0].data else {})
             .get("tls") or {}).get("error") if snapshots else None),
        "grants": [{"id": grant.id, "status": grant.status, "level": grant.level,
                    "principal": grant.principal,
                    "requested_by": grant.requested_by,
                    "approved_by": grant.approved_by,
                    "valid_until": grant.valid_until.isoformat(),
                    "targets": [{"type": t.target_type, "value": t.target_value}
                                for t in grant.targets]}
                   for grant in grants],
    })
    return {"data": data}


GEOIP_URL = os.environ.get("PLATFORM_GEOIP_URL", "").strip()
GEOIP_TTL_DAYS = 7


def _geo_normalise(payload: dict) -> dict:
    """One shape whatever the provider answered with.

    Every free geolocator names the same five facts differently; the page should
    not care which one is configured.
    """
    def pick(*keys):
        for key in keys:
            value = payload.get(key)
            if value not in (None, ""):
                return value
        return None

    lat = pick("lat", "latitude")
    lon = pick("lon", "longitude", "lng")
    try:
        lat, lon = float(lat), float(lon)
    except (TypeError, ValueError):
        return {}
    return {
        "latitude": lat, "longitude": lon,
        "country": pick("country", "country_name"),
        "country_code": pick("country_code", "countryCode"),
        "region": pick("region", "regionName"),
        "city": pick("city"),
        "organisation": pick("org", "organisation", "organization", "isp"),
        "asn": pick("as", "asn"),
        "timezone": pick("timezone"),
    }


@router.get("/assets/{asset_id}/geo")
def asset_geo(asset_id: str, refresh: bool = False,
              org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session)):
    """Where the addresses of this asset sit, cached per address.

    No geolocator configured is a valid deployment, not a failure: the page shows
    an empty map with the reason instead of inventing a location.
    """
    asset = session.get(models.Asset, asset_id)
    if asset is None or asset.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
    latest = _latest_observation(session, asset) or {}
    addresses = list(latest.get("ipv4") or []) + list(latest.get("ipv6") or [])
    if not addresses:
        return {"available": False, "reason": "no address observed for this asset",
                "points": []}
    if not GEOIP_URL:
        return {"available": False,
                "reason": "no geolocator configured — set PLATFORM_GEOIP_URL on the API",
                "points": []}

    points = []
    cutoff = models.utcnow() - datetime.timedelta(days=GEOIP_TTL_DAYS)
    for address in addresses[:8]:
        row = (session.query(models.AssetGeo)
               .filter_by(asset_id=asset.id, address=address).first())
        fresh = (row is not None and row.fetched_at is not None
                 and (row.fetched_at if row.fetched_at.tzinfo else
                      row.fetched_at.replace(tzinfo=datetime.timezone.utc)) > cutoff)
        if row is None or refresh or not fresh:
            url = GEOIP_URL.format(address=urllib.parse.quote(address))
            try:
                with urllib.request.urlopen(url, timeout=6) as response:
                    payload = json.load(response)
            except (urllib.error.URLError, OSError, ValueError) as error:
                payload = {"error": str(error)}
            normalised = _geo_normalise(payload) if "error" not in payload else {}
            if row is None:
                row = models.AssetGeo(id=models.uuid_hex(), org_id=org.id,
                                      asset_id=asset.id, address=address)
                session.add(row)
            row.data = json.dumps(normalised) if normalised else json.dumps(
                {"error": payload.get("error") or "unusable answer"})
            row.source = "geoip"
            row.fetched_at = models.utcnow()
            session.commit()
        try:
            stored = json.loads(row.data or "{}")
        except (TypeError, ValueError):
            stored = {}
        if stored.get("latitude") is not None:
            points.append({"address": address, **stored,
                           "fetched_at": row.fetched_at.isoformat() if row.fetched_at else None})
    return {"available": bool(points), "points": points,
            "reason": None if points else "the geolocator returned no usable answer"}


class RequestIn(BaseModel):
    level: str = Field(default="simple", max_length=16)
    actor: str = Field(default="console", max_length=255)


@router.post("/assets/{asset_id}/request")
def request_asset_authorization(asset_id: str, payload: RequestIn = None,
                                org: models.Organization = Depends(auth.require_org),
                                session: Session = Depends(get_session)):
    """Ask for permission on an asset that already exists.

    The same question a declaration asks, for a domain recorded before this flow
    existed or one whose request was rejected. Never grants anything.
    """
    from backend.app import authorization

    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.level not in authorization.SCAN_LEVELS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"level must be one of {sorted(authorization.SCAN_LEVELS)}")
    asset = session.get(models.Asset, asset_id)
    if asset is None or asset.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
    decision = authorization.ensure_authorization(
        session, org.id, asset, payload.actor, level=payload.level)
    _audit_log(session, org.id, payload.actor, "asset.authorization_requested",
               "asset", asset.id,
               f"{payload.level}: "
               + ("already covered" if decision["covered"] else
                  "excluded from scope" if decision["excluded"] else
                  f"request {decision['request']['id'][:8]}"))
    session.commit()
    return {"data": decision}


class AssetPatch(BaseModel):
    # A declared value is data a human typed: a typo has to be fixable without
    # deleting the asset and losing its links, snapshots and history. Renaming
    # does not move a scope target or a grant — those record the old value.
    value: str | None = Field(default=None, min_length=1, max_length=1024)
    type: str | None = None
    owner: str | None = Field(default=None, max_length=255)
    project: str | None = Field(default=None, max_length=128)
    classification_status: str | None = None
    notes: str | None = Field(default=None, max_length=8192)
    detail: str | None = Field(default=None, max_length=4096)
    actor: str | None = Field(default=None, max_length=255)


@router.patch("/assets/{asset_id}")
def patch_asset(asset_id: str, payload: AssetPatch = None,
                org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    """Ownership and classification only. Scope authorization is a separate
    decision and is never granted by confirming that an asset is ours."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    asset = session.get(models.Asset, asset_id)
    if asset is None or asset.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
    changes = []
    next_type = payload.type if payload.type is not None else asset.type
    next_value = payload.value.strip() if payload.value is not None else asset.value
    if payload.type is not None or payload.value is not None:
        if next_type not in models.ASSET_TYPES:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"type must be one of {sorted(models.ASSET_TYPES)}")
        if not next_value:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "value required")
        if next_type in {"domain", "subdomain", "api"}:
            next_value = next_value.lower()
            if "://" in next_value:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                    "give the hostname, not a URL, for a domain")
        if (next_type, next_value) != (asset.type, asset.value):
            clash = (session.query(models.Asset)
                     .filter_by(org_id=org.id, type=next_type, value=next_value)
                     .one_or_none())
            if clash is not None and clash.id != asset.id:
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    f"{next_type} {next_value} already exists in this organization")
            changes.append(f"{asset.type}:{asset.value} -> {next_type}:{next_value}")
            asset.type = next_type
            asset.value = next_value
    if payload.owner is not None:
        asset.owner = payload.owner.strip() or None
        changes.append(f"owner={asset.owner or 'none'}")
    if payload.project is not None:
        previous = asset.project_id
        if payload.project == "":
            asset.project_id = None
            changes.append("project=none")
            inherited = _cascade_project(session, org.id, asset, previous)
        else:
            project_row = (session.query(models.Project)
                           .filter_by(org_id=org.id, slug=payload.project).one_or_none())
            if project_row is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
            asset.project_id = project_row.id
            inherited = _cascade_project(session, org.id, asset, previous)
            changes.append(f"project={project_row.slug}")
            if inherited:
                changes.append(f"{inherited} descendant(s) inherited it")
    if payload.classification_status is not None:
        if payload.classification_status not in models.ASSET_CLASSIFICATION:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"classification_status must be one of "
                                f"{sorted(models.ASSET_CLASSIFICATION)}")
        asset.classification_status = payload.classification_status
        changes.append(f"classification={payload.classification_status}")
    if payload.notes is not None:
        asset.notes = payload.notes
        changes.append("notes")
    if payload.detail is not None:
        asset.detail = payload.detail
        changes.append("detail")
    if not changes:
        return {"data": _asset_data(session, asset), "changed": False}
    _audit_log(session, org.id, payload.actor or "system", "asset.updated",
               "asset", asset.id, ", ".join(changes))
    session.commit()
    return {"data": _asset_data(session, asset), "changed": True}


def _set_archived(asset_id: str, actor: str | None, archived: bool, org, session):
    asset = session.get(models.Asset, asset_id)
    if asset is None or asset.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
    if (asset.archived_at is not None) == archived:
        return {"data": _asset_data(session, asset), "changed": False}
    asset.archived_at = models.utcnow() if archived else None
    _audit_log(session, org.id, actor or "system",
               "asset.archived" if archived else "asset.unarchived",
               "asset", asset.id, asset.value)
    session.commit()
    return {"data": _asset_data(session, asset), "changed": True}


@router.post("/assets/{asset_id}/archive")
def archive_asset(asset_id: str, actor: str | None = Query(default=None),
                  org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    """Archive keeps every relation and the whole history; it only leaves the
    default inventory view."""
    return _set_archived(asset_id, actor, True, org, session)


@router.post("/assets/{asset_id}/unarchive")
def unarchive_asset(asset_id: str, actor: str | None = Query(default=None),
                    org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    return _set_archived(asset_id, actor, False, org, session)


class AssetIn(BaseModel):
    type: str
    value: str = Field(min_length=1, max_length=1024)
    detail: str | None = Field(default=None, max_length=4096)
    # Declaring the same domain from the Assets screen may still say where it
    # belongs; a WordPress has a project and no code, and both are optional.
    project: str | None = Field(default=None, max_length=128)
    deployment_id: str | None = Field(default=None, max_length=36)
    level: str = Field(default="simple", max_length=16)
    actor: str | None = None


@router.post("/assets")
def add_asset(payload: AssetIn = None,
              org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session)):
    """Record an asset. Recording never grants permission: when no active grant
    already covers it, the same transaction opens a request in Grants, which is
    the only place an administrator can turn it into authority."""
    from backend.app import authorization

    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.type not in models.ASSET_TYPES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"type must be one of {sorted(models.ASSET_TYPES)}")
    if payload.level not in authorization.SCAN_LEVELS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"level must be one of {sorted(authorization.SCAN_LEVELS)}")
    value = payload.value.strip()
    if payload.type in {"domain", "subdomain", "api"}:
        value = value.lower()
    project = None
    if payload.project:
        project = (session.query(models.Project)
                   .filter_by(org_id=org.id, slug=payload.project).one_or_none())
        if project is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    deployment = None
    if payload.deployment_id:
        deployment = session.get(models.Deployment, payload.deployment_id)
        if deployment is None or deployment.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "deployment not found")

    existing = (session.query(models.Asset)
                .filter_by(org_id=org.id, type=payload.type, value=value)
                .one_or_none())
    if existing is not None:
        existing.last_seen_at = models.utcnow()
        if payload.detail:
            existing.detail = payload.detail
        if project is not None:
            existing.project_id = project.id
            existing.classification_status = "owned"
        asset = existing
        already_known = True
    else:
        asset = models.Asset(org_id=org.id, type=payload.type, value=value,
                             source="manual", detail=payload.detail,
                             project_id=project.id if project else None,
                             classification_status=("owned" if project else
                                                    "unclassified"),
                             discovered_at=models.utcnow(),
                             last_seen_at=models.utcnow())
        session.add(asset)
        session.flush()
        already_known = False
    if deployment is not None:
        link = (session.query(models.AssetLink)
                .filter_by(org_id=org.id, asset_id=asset.id,
                           entity_type="deployment", entity_id=deployment.id).one_or_none())
        if link is None:
            session.add(models.AssetLink(
                org_id=org.id, asset_id=asset.id, entity_type="deployment",
                entity_id=deployment.id, relation="exposes",
                added_by=payload.actor or "console", added_at=models.utcnow()))

    decision = authorization.ensure_authorization(
        session, org.id, asset, payload.actor or "console", level=payload.level)
    _audit_log(session, org.id, payload.actor or "system", "asset.added",
               "asset", asset.id,
               f"{payload.type}:{value}"
               + (f" -> {project.slug}" if project else " (standalone)")
               + ("; authorization requested" if decision.get("request") else
                  "; already covered" if decision["covered"] else
                  "; excluded from scope"))
    session.commit()
    return {"data": {"id": asset.id, "type": asset.type, "value": asset.value},
            "already_known": already_known, "authorization": decision}


class DiscoveryIn(BaseModel):
    domain: str = Field(min_length=3, max_length=255)
    actor: str | None = None


@router.post("/assets/discover")
def discover(payload: DiscoveryIn = None,
             org: models.Organization = Depends(auth.require_org),
             session: Session = Depends(get_session)):
    """Certificate-transparency sweep; dedupes against the asset table."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    now = models.utcnow()
    created = refreshed = 0
    try:
        found = crtsh_subdomains(payload.domain)
    except Exception as error:  # noqa: BLE001 — catalog outages surface honestly
        raise HTTPException(status.HTTP_502_BAD_GATEWAY,
                            f"crt.sh sweep failed: {type(error).__name__}") from None
    for subdomain in found:
        existing = (session.query(models.Asset)
                    .filter_by(org_id=org.id, type="domain", value=subdomain)
                    .one_or_none())
        if existing is not None:
            existing.last_seen_at = now
            refreshed += 1
            continue
        session.add(models.Asset(org_id=org.id, type="domain", value=subdomain,
                                 source="crtsh", discovered_at=now, last_seen_at=now))
        created += 1
    seed = (session.query(models.Asset)
            .filter_by(org_id=org.id, type="domain", value=payload.domain)
            .one_or_none())
    # A sweep is discovery, not a decision: the new candidates are ours when the
    # parent is already filed, and stay unclassified when nobody claimed it.
    sweep_project = _ancestor_project(session, org.id, seed) if seed else None
    if seed is not None:
        seed.last_seen_at = now
        seed.source = "seed" if seed.source == "seed" else seed.source
        if seed.project_id:
            _cascade_project(session, org.id, seed)
    else:
        session.add(models.Asset(org_id=org.id, type="domain", value=payload.domain,
                                 source="seed", discovered_at=now, last_seen_at=now))
        created += 0  # seed row: inventory point, not a subdomain discovery
    _audit_log(session, org.id, payload.actor or "system", "easm.sweep",
               None, None, f"{payload.domain}: {created} new / {refreshed} refreshed")
    session.commit()
    return {"data": {"domain": payload.domain, "created": created,
                     "refreshed": refreshed, "total_known": created + refreshed + 1}}


class SnapshotIn(BaseModel):
    data: dict
    source: str = Field(default="manual", max_length=64)
    actor: str | None = None


def _snapshot_data(row: models.AssetSnapshot) -> dict:
    import json as _json

    return {"id": row.id, "observed_at": row.observed_at.isoformat(),
            "source": row.source, "data": _json.loads(row.data)}


def _diff(previous: dict, current: dict) -> list[dict]:
    """Flat key diff over the structured observation (nested dicts compare
    via their JSON rendering — honest for this payload shape)."""
    import json as _json

    changes = []
    keys = sorted(set(previous) | set(current))
    for key in keys:
        before, after = previous.get(key), current.get(key)
        if before != after:
            changes.append({"field": key,
                            "before": _json.dumps(before, sort_keys=True)
                            if isinstance(before, (dict, list)) else before,
                            "after": _json.dumps(after, sort_keys=True)
                            if isinstance(after, (dict, list)) else after})
    return changes


@router.post("/assets/{asset_id}/snapshots")
def add_snapshot(asset_id: str, payload: SnapshotIn = None,
                 org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    """Record an observation (passive DNS/TLS/tech metadata supplied by a
    passive collector or entered manually). Snapshotting never authorizes
    active testing."""
    import json as _json

    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    asset = session.get(models.Asset, asset_id)
    if asset is None or asset.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
    now = models.utcnow()
    row = models.AssetSnapshot(
        org_id=org.id, asset_id=asset.id, observed_at=now,
        source=payload.source, data=_json.dumps(payload.data, sort_keys=True),
        created_at=now)
    session.add(row)
    asset.last_seen_at = now
    session.flush()
    _audit_log(session, org.id, payload.actor or "system", "asset.snapshot",
               "asset", asset.id, f"{payload.source}: {len(payload.data)} fields")
    session.commit()
    return {"data": _snapshot_data(row)}


@router.get("/assets/{asset_id}/snapshots")
def list_snapshots(asset_id: str,
                   org: models.Organization = Depends(auth.require_org),
                   session: Session = Depends(get_session)):
    asset = session.get(models.Asset, asset_id)
    if asset is None or asset.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
    rows = (session.query(models.AssetSnapshot)
            .filter_by(org_id=org.id, asset_id=asset.id)
            .order_by(models.AssetSnapshot.observed_at.desc()).all())
    return {"data": [_snapshot_data(r) for r in rows], "total": len(rows)}


@router.get("/assets/{asset_id}/changes")
def asset_changes(asset_id: str,
                  org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    """Diff of the two most recent snapshots (plus the full change history)."""
    asset = session.get(models.Asset, asset_id)
    if asset is None or asset.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
    rows = (session.query(models.AssetSnapshot)
            .filter_by(org_id=org.id, asset_id=asset.id)
            .order_by(models.AssetSnapshot.observed_at).all())
    if len(rows) < 2:
        return {"data": {"asset": asset.value, "snapshots": len(rows),
                         "latest_changes": [], "history": []}}
    import json as _json

    history = []
    latest_changes = []
    for previous, current in zip(rows, rows[1:]):
        changes = _diff(_json.loads(previous.data), _json.loads(current.data))
        entry = {"from": previous.observed_at.isoformat(),
                 "to": current.observed_at.isoformat(), "changes": changes}
        history.append(entry)
    latest_changes = history[-1]["changes"] if history else []
    return {"data": {"asset": asset.value, "snapshots": len(rows),
                     "latest_changes": latest_changes, "history": history}}


def _dns_lookup(host: str) -> dict:
    """Resolve A/AAAA records. DNS resolution is discovery, not authorization."""
    import socket

    addresses = {"ipv4": [], "ipv6": []}
    try:
        for family, _type, _proto, _canon, sockaddr in socket.getaddrinfo(
                host, None, proto=socket.IPPROTO_TCP):
            ip = sockaddr[0]
            bucket = "ipv6" if ":" in ip else "ipv4"
            if ip not in addresses[bucket]:
                addresses[bucket].append(ip)
    except socket.gaierror as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY,
                            f"dns resolution failed: {exc}") from exc
    return addresses


def _tls_probe(host: str, port: int = 443, timeout: float = 6.0) -> dict:
    """Fetch the presented certificate metadata (an active connection)."""
    import socket
    import ssl

    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
                return {"issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "tls_version": tls.version(),
                        "cipher": (tls.cipher() or [None])[0]}
    except ssl.SSLCertVerificationError as exc:
        return {"error": f"certificate verification failed: {exc.verify_message}"}
    except (socket.timeout, OSError) as exc:
        return {"error": f"tls probe failed: {exc}"}


class CollectIn(BaseModel):
    tls: bool = False
    port: int = Field(default=443, ge=1, le=65535)
    actor: str = Field(min_length=2, max_length=255)


@router.post("/assets/{asset_id}/collect")
def collect(asset_id: str, payload: CollectIn = None,
            org: models.Organization = Depends(auth.require_org),
            session: Session = Depends(get_session)):
    """Passive DNS discovery plus optional active TLS probe.

    DNS stays discovery: it needs `passive_discovery` authorization. Opening
    a TLS connection is active verification and needs `active_verification`
    for that exact domain — discovering a host never authorizes touching it.
    """
    from backend.app import authorization

    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    asset = session.get(models.Asset, asset_id)
    if asset is None or asset.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
    if asset.type not in {"domain", "subdomain"}:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "collection supports domain assets only")
    target = [{"type": "domain", "value": asset.value}]
    # A grant narrowed to an environment only applies to that environment, so
    # the collector must name the one the asset is served from. An asset linked
    # to no deployment carries none, and an environment-restricted grant then
    # cannot match it — denied, not silently widened.
    deployment_environment = None
    link = (session.query(models.AssetLink)
            .filter_by(org_id=org.id, asset_id=asset.id,
                       entity_type="deployment", removed_at=None).first())
    if link is not None:
        deployment = session.get(models.Deployment, link.entity_id)
        if deployment is not None:
            deployment_environment = deployment.environment
    decision = authorization.authorize(
        session, org.id, payload.actor, "passive_discovery", target,
        tool="dns-collector", environment=deployment_environment)
    if decision["decision"] == "deny":
        _audit_log(session, org.id, payload.actor, "easm.collect_denied",
                   "asset", asset.id, decision["reason"][:300])
        session.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            f"not authorized: {decision['reason']}")
    observation: dict = {"dns": _dns_lookup(asset.value)}
    if payload.tls:
        tls_decision = authorization.authorize(
            session, org.id, payload.actor, "active_verification", target,
            tool="tls-probe", environment=deployment_environment)
        if tls_decision["decision"] == "deny":
            _audit_log(session, org.id, payload.actor, "easm.tls_denied",
                       "asset", asset.id, tls_decision["reason"][:300])
            session.commit()
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                f"tls probe not authorized: {tls_decision['reason']}")
        observation["tls"] = _tls_probe(asset.value, payload.port)

    now = models.utcnow()
    row = models.AssetSnapshot(
        org_id=org.id, asset_id=asset.id, observed_at=now,
        source="dns-collector" if not payload.tls else "dns+tls-collector",
        data=json.dumps(observation, sort_keys=True), created_at=now)
    session.add(row)
    asset.last_seen_at = now
    session.flush()
    _audit_log(session, org.id, payload.actor, "easm.collected", "asset",
               asset.id, f"{len(observation['dns']['ipv4'])} ipv4"
                         + (" +tls" if payload.tls else ""))
    session.commit()
    return {"data": {"snapshot_id": row.id, "observed_at": now.isoformat(),
                     "observation": observation}}


class ScheduleIn(BaseModel):
    strategy: str = Field(default="cron", max_length=32)
    expression: str = Field(min_length=1, max_length=255)
    enabled: bool = True
    actor: str | None = None


@router.get("/schedules")
def list_schedules(org: models.Organization = Depends(auth.require_org),
                   session: Session = Depends(get_session)):
    """List EASM scan schedules for the organization."""
    schedules = (session.query(models.ScanSchedule)
                 .filter_by(org_id=org.id)
                 .order_by(models.ScanSchedule.enabled.desc(),
                          models.ScanSchedule.created_at.desc()).all())
    return {"data": [{"id": s.id, "strategy": s.strategy,
                      "expression": s.expression, "enabled": s.enabled,
                      "next_run": s.next_run.isoformat() if s.next_run else None,
                      "created_at": s.created_at.isoformat()} for s in schedules]}


@router.post("/schedules", status_code=status.HTTP_201_CREATED)
def create_schedule(payload: ScheduleIn = None,
                   org: models.Organization = Depends(auth.require_org),
                   session: Session = Depends(get_session)):
    """Create an EASM scan schedule."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.strategy not in {"cron", "interval"}:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "strategy must be 'cron' or 'interval'")
    schedule = models.ScanSchedule(
        org_id=org.id, strategy=payload.strategy,
        expression=payload.expression, enabled=payload.enabled,
        actor=payload.actor or "system", created_at=models.utcnow())
    session.add(schedule)
    session.flush()
    _audit_log(session, org.id, payload.actor or "system", "easm.schedule.added",
               "schedule", schedule.id, payload.expression)
    session.commit()
    return {"data": {"id": schedule.id, "strategy": schedule.strategy,
                      "expression": schedule.expression, "enabled": schedule.enabled}}


@router.patch("/schedules/{schedule_id}", status_code=status.HTTP_200_OK)
def update_schedule(schedule_id: str, payload: ScheduleIn = None,
                    org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    """Update an EASM scan schedule."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    schedule = session.get(models.ScanSchedule, schedule_id)
    if schedule is None or schedule.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "schedule not found")
    if payload.strategy:
        schedule.strategy = payload.strategy
    if payload.expression:
        schedule.expression = payload.expression
    if payload.enabled is not None:
        schedule.enabled = payload.enabled
    session.commit()
    return {"data": {"id": schedule.id, "strategy": schedule.strategy,
                      "expression": schedule.expression, "enabled": schedule.enabled}}


@router.delete("/schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_schedule(schedule_id: str,
                    org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    """Delete an EASM scan schedule."""
    schedule = session.get(models.ScanSchedule, schedule_id)
    if schedule is None or schedule.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "schedule not found")
    session.delete(schedule)
    session.commit()
    return None


class SweepTrigger(BaseModel):
    actor: str | None = None
    domain: str | None = None
    asset_id: str | None = None


@router.post("/schedules/trigger")
def trigger_schedule(payload: SweepTrigger = None,
                     org: models.Organization = Depends(auth.require_org),
                     session: Session = Depends(get_session)):
    """Trigger a manual EASM sweep for testing."""
    from backend.app import authorization

    targets = []
    if payload.domain:
        targets.append({"type": "domain", "value": payload.domain})
    elif payload.asset_id:
        asset = session.get(models.Asset, payload.asset_id)
        if asset is None or asset.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
        targets.append({"type": "domain", "value": asset.value})

    if not targets:
        assets = session.query(models.Asset).filter_by(org_id=org.id).all()
        targets = [{"type": a.type, "value": a.value} for a in assets]

    for target in targets:
        decision = authorization.authorize(
            session, org.id, payload.actor or "system",
            "passive_discovery" if target["type"] == "domain" else "asset.collection",
            target, tool="easm-scheduler")
        if decision["decision"] == "deny":
            _audit_log(session, org.id, payload.actor or "system",
                       "easm.trigger_denied", "asset", None, decision["reason"][:300])
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                               f"not authorized: {decision['reason']}")

    result = {"sweeps": [], "total": len(targets), "denied": 0}
    for target in targets:
        domain = target["value"]
        try:
            found = crtsh_subdomains(domain)
            result["sweeps"].append({"domain": domain, "subdomains_found": len(found)})
        except Exception as e:
            result["sweeps"].append({"domain": domain, "error": str(e)})
            result["denied"] += 1

    _audit_log(session, org.id, payload.actor or "system",
               "easm.sweep.triggered", "asset", None,
               f"{len(targets)} targets, {result['denied']} denied")
    session.commit()
    return {"data": result}

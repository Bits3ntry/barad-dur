"""The advisory clock: feeds and re-resolution, on a schedule.

An SBOM is a photograph of the day the scanner ran. The artifact keeps its
authority — it says what Trivy knew then, and no later run may rewrite that
statement. What an artifact cannot say is what is known *now*: advisories are
published after every scan, EPSS moves every day, and CISA adds to KEV.

This module is that second clock. It never touches a component, a link or an
import: it refreshes the KEV/EPSS catalogues and re-asks OSV about the
inventory of each current build, adding only the findings that were not there
before. Old findings are refreshed, never deleted — a CVE that stopped matching
is evidence about the world, not permission to forget it.

The scheduler ticks often (every minute in the reference deployment); this job
decides whether it is *due*, so "daily" is a setting rather than a second cron.
"""
from __future__ import annotations

import datetime
import json
import os
import threading
import time

from sqlalchemy.orm import Session

from backend.app import models, vulns

ROW_NAME = "advisories"

# Defaults are the honest minimum: the two free catalogues and OSV. Trivy's DB
# refresh is opt-in because it downloads a ~100 MB artefact and needs an engine
# on the platform host, which a console-only deployment does not have.
DEFAULTS = {
    "enabled": True,
    "kev": True,
    "epss": True,
    "osv": True,
    "interval_hours": 24,
    "max_versions": 25,
    "ecosystems": [],
}

# purl type → what the operator sees in settings. Kept here so the settings
# screen and the filter cannot drift apart.
ECOSYSTEMS = ("npm", "pypi", "golang", "maven", "gem", "cargo", "nuget", "composer")


def _row(session: Session) -> models.PlatformSetting | None:
    return session.get(models.PlatformSetting, ROW_NAME)


def _stored(session: Session) -> dict:
    row = _row(session)
    if row is None:
        return {}
    try:
        payload = json.loads(row.value or "{}")
    except ValueError:
        # A hand-edited row must not take the scheduler down: fall back to the
        # defaults and say so through `source`.
        return {"_unreadable": True}
    return payload if isinstance(payload, dict) else {}


def _normalise(raw: dict) -> dict:
    """Clamp a stored/requested payload into the shape the job can trust."""
    config = dict(DEFAULTS)
    for key in ("enabled", "kev", "epss", "osv"):
        if isinstance(raw.get(key), bool):
            config[key] = raw[key]
    for key in ("interval_hours", "max_versions"):
        value = raw.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            low, high = (1, 168) if key == "interval_hours" else (1, 500)
            config[key] = max(low, min(high, value))
    ecosystems = raw.get("ecosystems")
    if isinstance(ecosystems, list):
        config["ecosystems"] = [str(item).lower() for item in ecosystems
                                if str(item).lower() in ECOSYSTEMS]
    return config


def load(session: Session) -> dict:
    """The effective configuration, defaults included, plus the last run."""
    stored = _stored(session)
    config = _normalise(stored)
    config["last_tick_at"] = stored.get("last_tick_at")
    config["last_tick"] = stored.get("last_tick") or {}
    config["ecosystems_available"] = list(ECOSYSTEMS)
    row = _row(session)
    config["source"] = "database" if row is not None else "defaults"
    # Whether this process is allowed to run the clock at all, and how often it
    # looks. The UI must not promise a daily run when nobody started the worker.
    config["autorun"] = autorun_enabled()
    config["poll_seconds"] = poll_seconds()
    config["unreadable_row"] = bool(stored.get("_unreadable"))
    config["updated_at"] = row.updated_at.isoformat() if row is not None and row.updated_at else None
    config["updated_by"] = row.updated_by if row is not None else None
    return config


def save(session: Session, payload: dict, actor: str | None = None) -> dict:
    """Merge a partial update into the row; never clobber the last-run record."""
    row = _row(session)
    current = _stored(session)
    current.pop("_unreadable", None)
    config = _normalise({**current, **{key: value for key, value in payload.items()
                                       if value is not None}})
    if row is None:
        row = models.PlatformSetting(name=ROW_NAME, value="{}")
        session.add(row)
    merged = {**current, **config}
    row.value = json.dumps(merged, sort_keys=True)
    row.updated_at = models.utcnow()
    row.updated_by = actor
    session.flush()
    return load(session)


def _record_run(session: Session, counters: dict) -> None:
    row = _row(session)
    if row is None:
        row = models.PlatformSetting(name=ROW_NAME, value="{}")
        session.add(row)
    try:
        stored = json.loads(row.value or "{}")
    except ValueError:
        stored = {}
    stored["last_tick_at"] = models.utcnow().isoformat()
    stored["last_tick"] = {key: counters.get(key) for key in
                           ("status", "kev_rows", "epss_rows", "versions_analyzed",
                            "advisories_found", "findings_created",
                            "findings_refreshed", "components_skipped_unmapped")
                           if counters.get(key) is not None}
    row.value = json.dumps(stored, sort_keys=True)
    session.flush()


def _due(config: dict) -> tuple[bool, str | None]:
    """Whether the interval has elapsed, and when the next run is due."""
    last = config.get("last_tick_at")
    if not last:
        return True, None
    try:
        last_at = datetime.datetime.fromisoformat(last)
    except ValueError:
        return True, None
    if last_at.tzinfo is None:
        last_at = last_at.replace(tzinfo=datetime.timezone.utc)
    due_at = last_at + datetime.timedelta(hours=config["interval_hours"])
    now = models.utcnow()
    return now >= due_at, due_at.isoformat()


def _version_ecosystems(session: Session, version_id: str) -> set[str]:
    purls = [row[0] for row in
             (session.query(models.Component.purl)
              .join(models.VersionComponent,
                    models.VersionComponent.component_id == models.Component.id)
              .filter(models.VersionComponent.project_version_id == version_id,
                      models.Component.purl.isnot(None)).distinct().all())]
    found = set()
    for purl in purls:
        if purl and purl.startswith("pkg:"):
            found.add(purl[4:].split("/", 1)[0])
    return found


def current_versions(session: Session, org_id: str, limit: int,
                     ecosystems: list[str] | None = None) -> list[tuple]:
    """The newest build of every (project, component) in the organization.

    Re-resolving an old build would resurrect findings the world has moved past
    and spend database calls on a document nobody reads; "current" is the only
    set that can produce a *new* fact about today.
    """
    rows = (session.query(models.Project, models.ProjectVersion)
            .join(models.ProjectVersion, models.ProjectVersion.project_id == models.Project.id)
            .filter(models.Project.org_id == org_id)
            .order_by(models.ProjectVersion.created_at.desc())
            .all())
    wanted = {item.lower() for item in ecosystems or []}
    seen: set[tuple] = set()
    selected: list[tuple] = []
    for project, version in rows:
        key = (project.id, version.component_id)
        if key in seen:
            continue
        seen.add(key)
        if wanted:
            present = _version_ecosystems(session, version.id)
            if not (present & wanted):
                continue
        selected.append((project, version))
        if len(selected) >= limit:
            break
    return selected


def _blank(config: dict) -> dict:
    return {"status": "ok", "interval_hours": config["interval_hours"],
            "kev_rows": 0, "epss_rows": 0, "versions_analyzed": 0,
            "components_queried": 0, "components_skipped_unmapped": 0,
            "advisories_found": 0, "findings_created": 0,
            "findings_refreshed": 0, "truncated": False, "errors": [],
            # Who was told, so "found 12 CVEs" and "told nobody" cannot look the
            # same in the run record.
            "notified": []}


def _gate(config: dict, force: bool, counters: dict) -> bool:
    """Whether this call should do any work at all."""
    if not config["enabled"]:
        counters["status"] = "disabled"
        return False
    due, next_due = _due(config)
    counters["next_due_at"] = next_due
    if not due and not force:
        counters["status"] = "not_due"
        return False
    return True


def _feeds(session: Session, config: dict, counters: dict,
           kev_fetch, epss_fetch) -> None:
    """KEV and EPSS are deployment-wide: one fetch serves every organization."""
    now = models.utcnow()
    if config["kev"]:
        from backend.app.routers.intelligence import fetch_kev
        try:
            rows = (kev_fetch or fetch_kev)()
            for row in rows:
                session.merge(models.KevEntry(**row, fetched_at=now))
                counters["kev_rows"] += 1
        except Exception as error:  # noqa: BLE001 — a feed outage is a fact, not a crash
            counters["errors"].append({"source": "kev",
                                       "error": f"{type(error).__name__}: {error}"})
    if config["epss"]:
        from backend.app.routers.intelligence import fetch_epss
        held = sorted({row.cve_id for row in session.query(models.Vulnerability).all()
                       if row.cve_id})
        try:
            rows = (epss_fetch or fetch_epss)(cve_ids=held) if held else []
            for row in rows:
                session.merge(models.EpssScore(**row, fetched_at=now))
                counters["epss_rows"] += 1
            # An empty catalogue is a state, not a failure: nothing has been
            # resolved against OSV yet, so there is no CVE to score.
        except Exception as error:  # noqa: BLE001
            counters["errors"].append({"source": "epss",
                                       "error": f"{type(error).__name__}: {error}"})


SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def _announce(session: Session, org_id: str, created_ids: list[str],
              builds: set[str], counters: dict) -> None:
    """Tell the workspace what arrived, once per day per channel.

    Silence is the default: no channel subscribed, or nothing new, costs one
    query and no message. A notification that fires every sweep regardless would
    be noise, and noise is how a channel gets muted.
    """
    if not created_ids:
        return
    from backend.app.routers import notifications

    rows = (session.query(models.Finding, models.Vulnerability)
            .join(models.Vulnerability, models.Vulnerability.id == models.Finding.vulnerability_id)
            .filter(models.Finding.id.in_(created_ids)).all())
    if not rows:
        return
    cves = {advisory.cve_id for _finding, advisory in rows if advisory.cve_id}
    kev = {row.cve_id for row in
           session.query(models.KevEntry).filter(models.KevEntry.cve_id.in_(cves)).all()} if cves else set()
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding, _advisory in rows:
        key = (finding.severity or "UNKNOWN").upper()
        counts[key if key in counts else "UNKNOWN"] += 1
    worst = next((severity for severity in SEVERITY_ORDER if counts[severity]), "UNKNOWN")
    ordered = sorted(rows, key=lambda pair: SEVERITY_ORDER.index(
        (pair[0].severity or "UNKNOWN").upper())
        if (pair[0].severity or "UNKNOWN").upper() in SEVERITY_ORDER else len(SEVERITY_ORDER))
    where = ", ".join(sorted(builds)) or "the workspace"
    payload = {
        "title": f"{len(rows)} new advisories",
        "count": len(rows),
        "kev": len(kev),
        "worst": worst,
        "by_severity": counts,
        "builds": where,
        "message": (f"{len(rows)} new advisor{'y' if len(rows) == 1 else 'ies'} on {where}"
                    f" · worst {worst} · {len(kev)} in KEV"),
        "findings": [{"severity": (finding.severity or "UNKNOWN").upper(),
                      "title": finding.title, "url": finding.url}
                     for finding, _advisory in ordered[:25]],
    }
    results = notifications.notify(session, org_id, "advisory.new", payload,
                                   dedupe_suffix=models.utcnow().date().isoformat())
    counters["notified"] = [f"{item['channel']}:{item['result']}" for item in results]


def _sweep(session: Session, org_id: str, config: dict, counters: dict,
           analyze) -> None:
    """Re-ask OSV about one organization's current builds, then say what is new."""
    created: list[str] = []
    builds: set[str] = set()
    for project, version in current_versions(session, org_id, config["max_versions"],
                                             config["ecosystems"]):
        try:
            result = analyze(session, org_id, project, version)
        except Exception as error:  # noqa: BLE001
            counters["errors"].append({"source": "osv",
                                       "version": f"{project.slug}/{version.version}",
                                       "error": f"{type(error).__name__}: {error}"})
            continue
        counters["versions_analyzed"] += 1
        created.extend(result.get("created_ids") or [])
        if result.get("created_ids"):
            builds.add(f"{project.slug}/{version.version}")
        for key in ("components_queried", "components_skipped_unmapped",
                    "advisories_found", "findings_created", "findings_refreshed"):
            counters[key] += int(result.get(key) or 0)
        counters["truncated"] = bool(counters["truncated"] or result.get("truncated"))
        if result.get("error"):
            counters["errors"].append({"source": "osv",
                                       "version": f"{project.slug}/{version.version}",
                                       "error": str(result["error"])})
    _announce(session, org_id, created, builds, counters)


def _finish(session: Session, counters: dict) -> None:
    if counters["errors"] and counters["versions_analyzed"] == 0 and not counters["kev_rows"]:
        counters["status"] = "failed"
    _record_run(session, counters)


def run(session: Session, org_id: str, *, force: bool = False,
        kev_fetch=None, epss_fetch=None, analyze=None) -> dict:
    """Refresh the feeds and re-ask OSV about one organization's builds.

    Every failure is reported and isolated: a catalogue outage must not skip
    the OSV pass, and one broken build must not abort the rest of the sweep.
    """
    config = load(session)
    counters = _blank(config)
    if not _gate(config, force, counters):
        return counters
    _feeds(session, config, counters, kev_fetch, epss_fetch)
    if config["osv"]:
        _sweep(session, org_id, config, counters, analyze or vulns.analyze)
    _finish(session, counters)
    return counters


def run_all(session: Session, *, force: bool = False,
            kev_fetch=None, epss_fetch=None, analyze=None) -> dict:
    """Every organization in one pass, with one due-gate.

    The settings row is deployment-wide, so `last_tick_at` is too: iterating
    organizations *inside* one run is what keeps a multi-org install from
    treating the first organization as "the" clock.
    """
    config = load(session)
    counters = _blank(config)
    counters["organizations"] = 0
    if not _gate(config, force, counters):
        return counters
    _feeds(session, config, counters, kev_fetch, epss_fetch)
    if config["osv"]:
        worker = analyze or vulns.analyze
        for org in session.query(models.Organization).all():
            counters["organizations"] += 1
            _sweep(session, org.id, config, counters, worker)
    _finish(session, counters)
    return counters


# ---------------------------------------------------------------- in-process clock
# A second container plus an API key is two things to lose for a job the platform
# can run itself. The due-gate in the settings row is what keeps this honest: the
# poll rate only decides how quickly "due" is noticed, never how often it runs.

def autorun_enabled() -> bool:
    return os.environ.get("ADVISORIES_AUTORUN", "").strip().lower() in {"1", "true", "yes"}


def poll_seconds() -> int:
    try:
        value = int(os.environ.get("ADVISORIES_POLL_SECONDS", "300"))
    except ValueError:
        return 300
    return max(5, min(value, 86400))


def tick_once(session_factory, log=None) -> dict:
    """One iteration of the clock: open a session, decide, run, record.

    Split out of the thread so it can be tested: the failure this guards against
    (a `sessionmaker` handed where a session is expected) only appears at
    runtime, and a thread that dies silently is the worst possible outcome for a
    job whose whole promise is "it runs every day".
    """
    session = session_factory()
    if not hasattr(session, "close"):
        raise TypeError("session_factory must return a Session, not a sessionmaker")
    try:
        counters = run_all(session)
        if counters["status"] in ("ok", "failed"):
            session.commit()
            if log is not None:
                log(counters)
        else:
            session.rollback()
        return counters
    except Exception as error:  # noqa: BLE001 — the clock must not die
        session.rollback()
        counters = {"status": "error", "error": f"{type(error).__name__}: {error}"}
        if log is not None:
            log(counters)
        return counters
    finally:
        session.close()


def start_worker(session_factory, log=None) -> threading.Thread | None:
    """Start the clock inside this process; None when autorun is off.

    The poll rate only decides how quickly "due" is noticed — never how often the
    sweep runs, which the settings row owns.
    """
    if not autorun_enabled():
        return None
    interval = poll_seconds()

    def loop() -> None:
        while True:
            time.sleep(interval)
            tick_once(session_factory, log)

    thread = threading.Thread(target=loop, name="advisories-clock", daemon=True)
    thread.start()
    return thread

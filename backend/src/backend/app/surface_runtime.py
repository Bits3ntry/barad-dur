"""How many scans may run at once, and against whom.

The limits are data, not constants: an operator changes them from Settings and
they apply on the next claim, with no restart. Three numbers, three different
failures they prevent:

* `per_zone` — 200 subdomains of one domain are one owner's estate. Six workers
  hitting it at once is how an egress address ends up in a blocklist and how a
  customer reads "your platform is attacking me".
* `per_org` — one tenant with a big queue must not drain the platform for the
  others.
* `queue_ceiling` — refusing an upload at the door is honest and instant;
  accepting it and never running it is neither.

What is NOT here: how many workers exist. Barad-dûr runs in Docker, and the
replica count belongs to the orchestrator — an app that could scale its own
containers would need the Docker socket, which turns a console RCE into root on
the host. The app reads the pool and shows it.
"""
from __future__ import annotations

import json

from sqlalchemy.orm import Session

from backend.app import authorization, models

SETTING_NAME = "surface_runtime"

DEFAULTS = {
    "per_zone": 2,
    "per_org": 4,
    "per_worker": 1,
    "queue_ceiling": 500,
    # The pool is never empty: a queue with nobody to drain it is the same bug as
    # a broken scanner, and the operator cannot tell them apart from the screen.
    "min_workers": 1,
    "max_workers": 6,
    "scale_down_after_s": 600,
}

# An operator may raise these, but not to the point where the limit stops
# meaning anything: eight parallel runs on a single zone is already a burst no
# target asked for, and a queue of 50k is a memory leak with a nicer name.
BOUNDS = {
    "per_zone": (1, 8),
    "per_org": (1, 32),
    "per_worker": (1, 4),
    "queue_ceiling": (50, 20000),
    "min_workers": (1, 4),
    "max_workers": (1, 16),
    "scale_down_after_s": (30, 3600),
}


def policy(session: Session) -> dict:
    """Stored policy with defaults filled in, so a partial row still answers."""
    row = session.query(models.PlatformSetting).filter_by(name=SETTING_NAME).first()
    document: dict = {}
    if row is not None:
        try:
            document = json.loads(row.value or "{}")
        except (TypeError, ValueError):
            document = {}
    merged = dict(DEFAULTS)
    for key, default in DEFAULTS.items():
        value = document.get(key, default)
        try:
            merged[key] = int(value)
        except (TypeError, ValueError):
            merged[key] = default
    return merged


def validate(payload: dict) -> dict:
    cleaned = {}
    for key, (low, high) in BOUNDS.items():
        if key not in payload:
            cleaned[key] = DEFAULTS[key]
            continue
        try:
            value = int(payload[key])
        except (TypeError, ValueError):
            raise ValueError(f"{key} must be a number") from None
        if not low <= value <= high:
            raise ValueError(f"{key} must be between {low} and {high}")
        cleaned[key] = value
    return cleaned


def save(session: Session, payload: dict, actor: str, org_id: str) -> dict:
    cleaned = validate(payload)
    row = session.query(models.PlatformSetting).filter_by(name=SETTING_NAME).first()
    before = policy(session)
    if row is None:
        row = models.PlatformSetting(name=SETTING_NAME, value=json.dumps(cleaned))
        session.add(row)
    else:
        row.value = json.dumps(cleaned)
    # The ledger is per-org and hash-chained, so the entry rides the appender
    # that keeps the chain: a limit change must be as traceable as a grant.
    from backend.app.routers.identity import _audit
    _audit(session, org_id, actor, "surface.runtime_limits",
           resource_type="platform_setting", resource_id=SETTING_NAME,
           detail=", ".join(f"{k} {before.get(k)} -> {v}" for k, v in cleaned.items()
                            if before.get(k) != v) or "no change")
    session.commit()
    return cleaned


def desired_workers(session: Session, org_id: str) -> dict:
    """How many worker replicas the queue asks for right now.

    No hysteresis here on purpose: this is the *target*, a pure function of the
    queue. The scaler owns the timer — it is the process that watches, so it is
    the one that knows how long the queue has been empty.
    """
    limits = policy(session)
    queued = (session.query(models.ScanJob)
              .filter_by(org_id=org_id, status="queued").count())
    busy, _per_zone = in_flight(session, org_id)
    per_worker = max(1, limits["per_worker"])
    needed = -(-(queued + busy) // per_worker)          # ceil, the pool covers the backlog
    target = max(limits["min_workers"], min(limits["max_workers"], needed))
    return {
        "target": target,
        "needed": needed,
        "queued": queued,
        "in_flight": busy,
        "min": limits["min_workers"],
        "max": limits["max_workers"],
        "idle_seconds": limits["scale_down_after_s"],
        "binding": ("max_workers" if needed > limits["max_workers"]
                    else "min_workers" if needed < limits["min_workers"]
                    else "queue"),
    }


def zone_of_targets(targets: list[dict]) -> str:
    """The owner of a target, not the host: every subdomain shares its zone.

    A CIDR keeps its own label; an address maps to itself. Anything we cannot
    place honestly becomes its own bucket, because grouping two unrelated
    targets under one zone would throttle a customer for someone else's queue.
    """
    for target in targets or []:
        if str(target.get("type") or "") in ("domain", "wildcard_domain", "url"):
            value = str(target.get("value") or "")
            if value.startswith(("http://", "https://")):
                value = value.split("//", 1)[1].split("/", 1)[0]
            value = value.split(":", 1)[0].lstrip("*.").lower()
            if value:
                return authorization.zone_of(value)
        if target.get("value"):
            return str(target["value"]).lower()
    return "ungrouped"


def zone_of_job(job: "models.ScanJob") -> str:
    try:
        targets = json.loads(job.targets or "[]")
    except (TypeError, ValueError):
        targets = []
    return zone_of_targets(targets)


def in_flight(session: Session, org_id: str) -> tuple[int, dict[str, int]]:
    """Jobs being executed right now, in total and per zone."""
    rows = (session.query(models.ScanJob)
            .filter_by(org_id=org_id)
            .filter(models.ScanJob.status.in_(["leased", "running"])).all())
    per_zone: dict[str, int] = {}
    for job in rows:
        zone = zone_of_job(job)
        per_zone[zone] = per_zone.get(zone, 0) + 1
    return len(rows), per_zone


def snapshot(session: Session, org_id: str) -> dict:
    """The policy plus the state it is acting on, for the Settings screen."""
    # A registration is not a worker. Counting rows said "7 online" while one
    # process was alive: a number nobody can trust is worse than no number.
    from backend.app.routers.orchestration import HEARTBEAT_STALE_SECONDS
    now = models.utcnow()
    registered = (session.query(models.Worker).filter_by(org_id=org_id).all())
    online = [row for row in registered
              if row.last_heartbeat is not None
              and (now - authorization._aware(row.last_heartbeat)).total_seconds()
              <= HEARTBEAT_STALE_SECONDS]
    queued = (session.query(models.ScanJob).filter_by(org_id=org_id, status="queued").count())
    busy, per_zone = in_flight(session, org_id)
    return {
        "workers_online": len(online),
        "workers_registered": len(registered),
        "pool": desired_workers(session, org_id),
        "queue": queued,
        "in_flight": busy,
        "per_zone": per_zone,
        "waiting": [
            {"job_id": job.id, "targets": job.targets, "zone": zone_of_job(job),
             "reason": _waiting_reason(job, per_zone, policy(session))}
            for job in (session.query(models.ScanJob)
                        .filter_by(org_id=org_id, status="queued")
                        .order_by(models.ScanJob.created_at).limit(5).all())
        ],
    }


def _waiting_reason(job, per_zone: dict[str, int], limits: dict) -> str:
    zone = zone_of_job(job)
    current = per_zone.get(zone, 0)
    if current >= limits["per_zone"]:
        return f"zone full: {current} in flight on {zone}"
    total = sum(per_zone.values())
    if total >= limits["per_org"]:
        return f"organization full: {total} in flight"
    return "waiting for a worker"


def admission(session: Session, org_id: str, targets: list[dict]) -> tuple[bool, str]:
    """May a new run be queued at all? Only the ceiling can refuse."""
    limits = policy(session)
    queued = (session.query(models.ScanJob)
              .filter_by(org_id=org_id, status="queued").count())
    if queued >= limits["queue_ceiling"]:
        return False, (f"queue ceiling reached ({queued}/{limits['queue_ceiling']}); "
                       "wait for the backlog to drain or raise the ceiling in "
                       "Settings → Runtime")
    return True, ""


def capacity(session: Session, org_id: str, targets: list[dict]) -> tuple[bool, str]:
    """May this job start now, given what is already in flight?"""
    limits = policy(session)
    total, per_zone = in_flight(session, org_id)
    if total >= limits["per_org"]:
        return False, f"organization full: {total} in flight (cap {limits['per_org']})"
    zone = zone_of_targets(targets)
    current = per_zone.get(zone, 0)
    if current >= limits["per_zone"]:
        return False, (f"zone full: {current} in flight on {zone} "
                       f"(cap {limits['per_zone']})")
    return True, ""

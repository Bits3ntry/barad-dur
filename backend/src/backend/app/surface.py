"""Attack-surface change detection over observations.

The rule that matters: only observations of **equal, complete coverage** are
comparable. A failed collection is not a closed port, a disappeared host or a
removed certificate — it is a coverage gap, and it is reported as one.

Categories implemented (v0):
  new_host            first observation of an asset
  open_port           a port present now and absent before
  closed_port         a port present before and absent now
  dns_changed         the address set changed
  technology_changed  the declared/observed technology set changed
  new_certificate     the certificate identity changed
  certificate_expiring  certificate expires within 30 days (a condition, not a change)
  host_disappeared    previously resolving, now no addresses — only when coverage is full
  dangling_dns        CNAME/alias observed with no address behind it (evidence in value)

Anything the observation cannot prove is listed under `coverage_notes`.
"""
import json
from datetime import datetime, timezone

COMPARABLE_COVERAGE = {"full"}
CERT_WARN_DAYS = 30


def _aware(value):
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _set(value, key) -> set:
    raw = (value or {}).get(key)
    if isinstance(raw, list):
        return {str(item).lower() for item in raw if item}
    if isinstance(raw, str) and raw:
        return {raw.lower()}
    return set()


def _ports(value, key="ports") -> set[int]:
    raw = (value or {}).get(key)
    items = raw if isinstance(raw, list) else ([raw] if raw else [])
    ports = set()
    for item in items:
        try:
            ports.add(int(str(item).strip()))
        except (TypeError, ValueError):
            continue
    return ports


def _cert_identity(value) -> str | None:
    cert = (value or {}).get("certificate") or {}
    if not isinstance(cert, dict):
        return None
    parts = [cert.get("subject"), cert.get("issuer"), cert.get("not_after"),
             cert.get("serial"), cert.get("fingerprint")]
    joined = "|".join(str(part) for part in parts if part)
    return joined or None


def diff(previous, current) -> dict:
    """Compare two observations of one asset/kind.

    Returns {comparable, changes[], coverage_notes[], current_conditions[]}.
    `current_conditions` are facts about the current observation that need a
    decision even without a previous one (e.g. certificate about to expire).
    """
    changes, notes, conditions = [], [], []
    if previous is None:
        notes.append("first observation for this asset: no comparison baseline")
        current_value = current.value if isinstance(current.value, dict) else {}
        return {"comparable": False, "changes": changes,
                "coverage_notes": notes,
                "current_conditions": _conditions(current_value, current)}

    before = previous.value if isinstance(previous.value, dict) else json.loads(
        previous.value or "{}")
    now = current.value if isinstance(current.value, dict) else json.loads(
        current.value or "{}")

    if previous.coverage not in COMPARABLE_COVERAGE or current.coverage not in COMPARABLE_COVERAGE:
        notes.append(
            f"not comparable: previous coverage {previous.coverage}, "
            f"current coverage {current.coverage}")
        return {"comparable": False, "changes": changes,
                "coverage_notes": notes,
                "current_conditions": _conditions(now, current)}

    before_ports, now_ports = _ports(before), _ports(now)
    for port in sorted(now_ports - before_ports):
        changes.append({"category": "open_port", "subject": current.subject,
                        "port": port, "before": None, "after": port,
                        "detail": f"port {port} is newly reachable"})
    for port in sorted(before_ports - now_ports):
        changes.append({"category": "closed_port", "subject": current.subject,
                        "port": port, "before": port, "after": None,
                        "detail": f"port {port} was reachable before and is not now"})

    before_addresses = _set(before, "addresses") or _set(before, "ipv4")
    now_addresses = _set(now, "addresses") or _set(now, "ipv4")
    if before_addresses and now_addresses and before_addresses != now_addresses:
        changes.append({"category": "dns_changed", "subject": current.subject,
                        "before": sorted(before_addresses),
                        "after": sorted(now_addresses),
                        "detail": "the address set changed"})
    if before_addresses and not now_addresses:
        changes.append({"category": "host_disappeared", "subject": current.subject,
                        "before": sorted(before_addresses), "after": [],
                        "detail": "no addresses observed in a complete collection"})

    before_tech, now_tech = _set(before, "technology") or _set(before, "tech"), \
        _set(now, "technology") or _set(now, "tech")
    if before_tech != now_tech and (before_tech or now_tech):
        changes.append({"category": "technology_changed", "subject": current.subject,
                        "before": sorted(before_tech), "after": sorted(now_tech),
                        "detail": "the observed technology set changed"})

    before_cert, now_cert = _cert_identity(before), _cert_identity(now)
    if before_cert and now_cert and before_cert != now_cert:
        changes.append({"category": "new_certificate", "subject": current.subject,
                        "before": before_cert, "after": now_cert,
                        "detail": "the certificate identity changed"})
    if (now.get("dangling") or (now.get("dns") or {}).get("dangling")):
        conditions.append({"category": "dangling_dns", "subject": current.subject,
                           "detail": "alias observed without an address behind it"})

    conditions.extend(_conditions(now, current))
    return {"comparable": True, "changes": changes,
            "coverage_notes": notes, "current_conditions": conditions}


def _conditions(value: dict, observation) -> list[dict]:
    conditions = []
    cert = (value or {}).get("certificate") or {}
    not_after = cert.get("not_after")
    if not_after:
        try:
            expiry = datetime.fromisoformat(str(not_after).replace("Z", "+00:00"))
            days = (_aware(expiry) - datetime.now(timezone.utc)).days
            if days <= CERT_WARN_DAYS:
                conditions.append({
                    "category": "certificate_expiring",
                    "subject": observation.subject,
                    "detail": f"certificate expires in {days} days",
                    "days_left": days, "severity": "HIGH" if days <= 7 else "MEDIUM"})
        except ValueError:
            conditions.append({"category": "certificate_expiring",
                               "subject": observation.subject,
                               "detail": "certificate expiry could not be read",
                               "unknown": True})
    return conditions


def event_severity(category: str) -> str:
    return {"open_port": "MEDIUM", "host_disappeared": "HIGH",
            "dangling_dns": "HIGH", "certificate_expiring": "MEDIUM",
            "new_host": "LOW", "dns_changed": "LOW",
            "technology_changed": "LOW", "new_certificate": "LOW",
            "closed_port": "LOW"}.get(category, "MEDIUM")

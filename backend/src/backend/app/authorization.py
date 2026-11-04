"""BL-015: the scan authorization engine.

Invariants, enforced here and nowhere else:
- Discovery != authorization: only explicit grants allow active work.
- Default deny for every capability beyond passive_discovery.
- Explicit denials (org scope exclusions) prevail over grants.
- A grant on `*.empresa.com` never covers `empresa.com` itself, IP-address
  targets, or third-party domains — only its own subdomains.
- Redirects/DNS resolutions can never widen an authorized target.
- Decisions carry the policy version and a human-readable reason.
"""
import datetime
import ipaddress
import json
from urllib.parse import urlparse

from backend.app import models

# BL-015 catalog: capability-level trust, never scanner-name trust.
CAPABILITIES = {
    "passive_discovery": "certificate transparency, DNS records, catalog reads — no target contact beyond name resolution of the granted value",
    "active_verification": "probe an authorized host/service as it exists (TLS inspection, banner grab, version check)",
    "vulnerability_analysis": "engine evaluation over observed data (OSV/KEV matching, SBOM analysis)",
    "intrusive_testing": "active exploitation attempts (nuclei-class). Highest bar: grant + explicit denial not present",
}
CAPABILITY_LEVELS = ["passive_discovery", "active_verification",
                     "vulnerability_analysis", "intrusive_testing"]

POLICY_VERSION = 1

GRANT_TARGET_TYPES = {"domain", "wildcard_domain", "cidr", "ip", "url",
                      "endpoint", "repository", "service"}

ENVIRONMENT_EXECUTION_MODES: dict[str, str] = {}


def _now() -> datetime.datetime:
    return models.utcnow()


def _aware(value: datetime.datetime) -> datetime.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=datetime.timezone.utc)
    return value


def decision(denied: bool, reason: str, matched_group=None, checked=None) -> dict:
    """Explainable decision with the policy version pin."""
    out = {
        "decision": "deny" if denied else "allow",
        "policy_version": POLICY_VERSION,
        "reason": reason,
        "evaluated_at": _now().isoformat(),
    }
    if matched_group is not None:
        out["matched"] = matched_group
    if checked is not None:
        out["checked"] = checked
    return out


def _exact_or_wildcard(grant_type: str, grant_value: str,
                       target_type: str, target_value: str) -> bool:
    """Strict target match. A wildcard grant only stretches to its immediate
    own-domain names, never to the apex, sibling TLDs or unrelated hosts."""
    target_value = target_value.strip().lower()
    grant_value = grant_value.strip().lower()
    if grant_type == "wildcard_domain" and target_type in ("domain", "wildcard_domain"):
        if not grant_value.startswith("*."):
            return False
        base = grant_value[2:]
        if target_value == base:  # apex is NOT covered by *.base
            return False
        return target_value.endswith("." + base)
    if grant_type == target_type:
        return target_value == grant_value
    # cidr grants contain ip targets.
    if grant_type == "cidr" and target_type == "ip":
        try:
            return ipaddress.ip_address(target_value) in ipaddress.ip_network(grant_value, strict=False)
        except ValueError:
            return False
    # ip grants that are cidr-shaped still behave like cidr.
    if grant_type == "ip" and target_type == "ip":
        if "/" in grant_value:
            try:
                return ipaddress.ip_address(target_value) in ipaddress.ip_network(grant_value, strict=False)
            except ValueError:
                return False
    return False


def _url_matches(grant_value: str, target_value: str) -> bool:
    """Exact same-origin + same-path match; a URL grant never covers paths it
    does not declare (no broad-folder stretching)."""
    grant_value = grant_value.strip().rstrip("/")
    target_value = target_value.strip().rstrip("/")
    if grant_value == target_value:
        return True
    g = urlparse(grant_value if "//" in grant_value else f"https://{grant_value}")
    t = urlparse(target_value if "//" in target_value else f"https://{target_value}")
    return (g.scheme == t.scheme and g.netloc == t.netloc and g.path == t.path)


def _target_allowed(session, grant: models.ScanGrant,
                    target_type: str, target_value: str) -> bool:
    """Any of the grant's declared targets must cover the requested target."""
    for gt in grant.targets:
        if gt.target_type in ("url", "endpoint"):
            if _url_matches(gt.target_value, target_value):
                return True
        elif gt.target_type in ("repository", "service"):
            if target_type == gt.target_type and gt.target_value == target_value:
                return True
        else:
            if _exact_or_wildcard(gt.target_type, gt.target_value,
                              target_type, target_value):
                return True
    return False


def _denied_by_exclusion(session, org_id: str,
                         target_type: str, target_value: str):
    """The exclusion row that blocks this target, if any.

    Explicit exclusion wins over any grant. A **disabled** row is not an
    exclusion any more (that is how one is undone without deleting the audit
    trail), and an expired one has lapsed — both are skipped here and in
    `scoping.decide`, or the console would show "restored" while collection
    stays blocked.
    """
    now = _now()
    rows = (session.query(models.ScopeExclusion)
            .filter_by(org_id=org_id).all())
    for row in rows:
        if getattr(row, "status", "active") != "active":
            continue
        expires = _aware(row.expires_at) if getattr(row, "expires_at", None) else None
        if expires is not None and expires <= now:
            continue
        if _exact_or_wildcard(row.target_type, row.value,
                              target_type, target_value):
            return row
    return None


def authorize(session, org_id: str, principal: str, capability: str,
              targets: list[dict], tool: str | None = None,
              environment: str | None = None, at: datetime.datetime | None = None):
    """Authorize one operation: default deny, exclusion first, then the
    earliest active grant that covers EVERY requested target."""
    checked: list[dict] = []
    now = _aware(at or _now())

    if capability not in CAPABILITIES:
        return decision(True, f"unknown capability '{capability}'", checked=targets)

    for item in targets:
        checked.append({**item, "resolved": False})
        exclusion = _denied_by_exclusion(session, org_id, item["type"], item["value"])
        if exclusion is not None:
            return decision(True, f"explicit exclusion: {exclusion.reason}",
                            matched_group=["exclusion", exclusion.id], checked=checked)

    # The earliest active grant that covers the full request wins; nothing
    # else lifts the default deny.
    grants = (session.query(models.ScanGrant)
              .filter_by(org_id=org_id, status="active",
                         principal=principal)
              .order_by(models.ScanGrant.created_at).all())
    capabilities_wanted = {c for c in capability.split(",") if c}
    conditional_skips: list[str] = []
    environment_skips: list[str] = []
    tool_skips: list[str] = []
    for grant in grants:
        granted_caps = {c.strip() for c in grant.capabilities.split(",") if c.strip()}
        if not capabilities_wanted <= granted_caps:
            continue
        # A restriction the request cannot satisfy is not leniency: a grant
        # narrowed to a tool or an environment applies only when the request
        # names the same one. An unlabelled request matches nothing, because
        # "we cannot prove this is the permitted case" is a deny.
        if grant.tools:
            allowed_tools = {t.strip() for t in grant.tools.split(",") if t.strip()}
            if not tool:
                tool_skips.append(f"{grant.id} ({', '.join(sorted(allowed_tools))})")
                continue
            if tool not in allowed_tools:
                continue
        if grant.environment:
            if not environment:
                environment_skips.append(f"{grant.id} ({grant.environment})")
                continue
            if grant.environment != environment:
                continue
        if not (_aware(grant.valid_from) <= now <= _aware(grant.valid_until)):
            continue
        if grant.conditions is not None and grant.conditions.strip() not in ("", "{}", "null"):
            # BL-015 invariant: conditions the policy engine cannot evaluate
            # yet are NEVER satisfied by leniency — the grant is skipped and
            # the request stays denied until effective evaluation exists.
            conditional_skips.append(grant.id)
            continue
        covered = all(_target_allowed(session, grant, t["type"], t["value"])
                      for t in targets)
        if not covered:
            continue
        return decision(False,
                        f"granted by {grant.id} (capabilities {sorted(granted_caps)})",
                        matched_group=["grant", grant.id], checked=checked)

    if conditional_skips:
        return decision(
            True,
            f"matching grant(s) {conditional_skips} carry conditions whose "
            "evaluation the current policy does not support; denied until a "
            "supported evaluator exists",
            checked=checked)
    if environment_skips:
        return decision(
            True,
            f"grant(s) {environment_skips} are narrowed to an environment and "
            "this request declares none; name the environment to use them",
            checked=checked)
    if tool_skips:
        return decision(
            True,
            f"grant(s) {tool_skips} are narrowed to a tool and this request "
            "names none; name the tool to use them", checked=checked)
    return decision(True, "no active grant covers the requested capability+targets",
                    checked=checked)


def issue_grant(session, org_id: str, principal: str, capabilities: list[str],
                targets: list[dict], issued_by: str, justification: str,
                environment: str | None = None, tools: list[str] | None = None,
                conditions: dict | None = None,
                valid_from: datetime.datetime | None = None,
                valid_until: datetime.datetime | None = None) -> models.ScanGrant:
    """Create a grant with the issuance guard: invasive capabilities are never
    self-authorized (issuer must differ from principal), mirroring the
    suppression no-self-approval rule."""
    unknown = [c for c in capabilities if c not in CAPABILITIES]
    if unknown:
        raise ValueError(f"unknown capabilities: {unknown}")
    invasive = {"active_verification", "vulnerability_analysis", "intrusive_testing"} \
        & set(capabilities)
    if invasive and principal == issued_by:
        raise ValueError(
            "invasive capabilities cannot be self-authorized; issuer must differ")
    if not targets:
        raise ValueError("a grant needs at least one target")
    for t in targets:
        if t.get("type") not in GRANT_TARGET_TYPES:
            raise ValueError(f"unknown target type {t.get('type')!r}")
        if not t.get("value"):
            raise ValueError("target value required")
    now = _now()
    grant = models.ScanGrant(
        org_id=org_id, principal=principal,
        capabilities=",".join(capabilities),
        tools=",".join(tools) if tools else None,
        environment=environment,
        conditions=json.dumps(conditions, sort_keys=True) if conditions else None,
        issued_by=issued_by,
        justification=justification,
        policy_version=POLICY_VERSION,
        status="active",
        valid_from=valid_from or now,
        valid_until=valid_until or (now + datetime.timedelta(days=7)),
        created_at=now, updated_at=now)
    session.add(grant)
    session.flush()
    for t in targets:
        session.add(models.ScanGrantTarget(
            grant_id=grant.id, target_type=t["type"],
            target_value=t["value"].strip().lower()))
    return grant


def revoke_grant(session, grant: models.ScanGrant, actor: str, reason: str) -> None:
    """Mid-run revocation source of truth: revalidation reads status."""
    grant.status = "revoked"
    grant.revoked_at = _now()
    grant.revoked_by = actor
    grant.revocation_reason = reason
    grant.updated_at = _now()


def revalidate(session, grant_id: str, principal: str, capability: str,
               targets: list[dict], at: datetime.datetime | None = None):
    """Run-start revalidation: same authorize() but exact grant id — a grant
    that was valid at issue time can still be refused mid-lifecycle."""
    grant = session.get(models.ScanGrant, grant_id)
    if grant is None or grant.status != "active":
        return decision(True, f"grant {grant_id} is not active anymore")
    now = _aware(at or _now())
    if not (_aware(grant.valid_from) <= now <= _aware(grant.valid_until)):
        return decision(True, f"grant {grant_id} validity window lapsed")
    caps = {c.strip() for c in grant.capabilities.split(",") if c.strip()}
    if isinstance(capability, str):
        wanted = {c.strip() for c in capability.split(",") if c.strip()}
    else:
        wanted = set(capability or ())
    if not wanted <= caps:
        return decision(True, f"grant {grant_id} does not carry {sorted(wanted - caps)}")
    if not all(_target_allowed(session, grant, t["type"], t["value"]) for t in targets):
        return decision(True, f"grant {grant_id} does not cover the current targets")
    return decision(False, f"revalidated against {grant.id}",
                    matched_group=["grant", grant.id])

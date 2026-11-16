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

from sqlalchemy import delete as sa_delete

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
    """Strict target match. A wildcard grant only stretches to its own-domain
    names, never to the apex, sibling TLDs or unrelated hosts.

    Granting `*.x` is a statement about everything under `x`, not about `x`
    itself: the apex is usually the marketing site and a different service from
    the estate the operator had in mind. The console says so instead of guessing.
    """
    target_value = target_value.strip().lower()
    grant_value = grant_value.strip().lower()
    # A grant written before the normalisation above (or by hand) may carry the
    # wildcard in a `domain` row: the star is the permission, the label is not.
    is_wildcard = grant_type == "wildcard_domain" or (
        grant_type == "domain" and grant_value.startswith("*."))
    if is_wildcard and target_type in ("domain", "wildcard_domain"):
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


def _stored_target(kind: str, value: str) -> str:
    """How a granted target is kept.

    Domains are case-insensitive by DNS and are stored folded. A **URL is not**: the
    path is case-sensitive, and folding it here made the grant impossible to match
    in `_url_matches`, which compares paths exactly — a grant for
    `/api/Users/1` was stored as `/api/users/1` and then denied the very request it
    was issued for.
    """
    text = str(value).strip()
    if kind in ("domain", "wildcard_domain"):
        return text.lower()
    return text


def _url_matches(grant_value: str, target_value: str) -> bool:
    """Same origin and same path — with the origin itself as the whole origin.

    A grant that names a **path** covers exactly that path: `/Admin` and `/admin`
    are two different resources and no broad-folder stretching happens. A grant
    that names only the **origin** (`https://api.example:8443`) is a statement about
    the service, so it covers every path on it — without that rule every replay of
    a finding (which always names a path) needed a grant per URL, and the gate that
    authorizes a reproduction could never be satisfied.
    """
    grant_value = grant_value.strip().rstrip("/")
    target_value = target_value.strip().rstrip("/")
    if grant_value == target_value:
        return True
    g = urlparse(grant_value if "//" in grant_value else f"https://{grant_value}")
    t = urlparse(target_value if "//" in target_value else f"https://{target_value}")
    same_origin = (g.scheme.lower() == t.scheme.lower()
                   and g.netloc.lower() == t.netloc.lower())
    if not same_origin:
        return False
    return g.path == t.path or g.path == ""


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

    # A request may name several capabilities ("a,b") and every one of them must be
    # granted. Validating the whole string instead of its parts made a multi-step
    # scan impossible to authorize: the engine split it two lines below, but the
    # guard above had already refused it by name.
    capabilities_wanted = {part.strip() for part in str(capability or "").split(",")
                           if part.strip()}
    unknown = capabilities_wanted - set(CAPABILITIES)
    if unknown or not capabilities_wanted:
        return decision(True, f"unknown capability '{capability}'", checked=targets)

    for item in targets:
        checked.append({**item, "resolved": False})
        exclusion = _denied_by_exclusion(session, org_id, item["type"], item["value"])
        if exclusion is not None:
            return decision(True, f"explicit exclusion: {exclusion.reason}",
                            matched_group=["exclusion", exclusion.id], checked=checked)

    # The earliest active grant that covers the full request wins; nothing
    # else lifts the default deny.
    # A grant issued from the console records `console` as its principal; a run
    # resolved by the platform asks as `collector`. Both are the platform talking
    # to itself — a human is never either — so they honour each other's grants.
    # Filtering on the exact string made every console-issued grant invisible to
    # every cloud scan: the asset had permission and the plan said it had none.
    platform_principals = {COLLECTOR_PRINCIPAL, "console"}
    scope = {principal} | (platform_principals if principal in platform_principals else set())
    grants = [grant for grant in
              (session.query(models.ScanGrant)
               .filter_by(org_id=org_id, status="active")
               .order_by(models.ScanGrant.created_at).all())
              if grant.principal in scope]
    capabilities_wanted = {c.strip() for c in str(capability or "").split(",") if c.strip()}
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
        # `domain` + `*.example` is the same permission as `wildcard_domain`, and
        # the picker copies the type from the scope row, which stores patterns as
        # `domain`. Normalise at the door so the stored grant and its reading agree.
        if t["type"] == "domain" and t["value"].strip().startswith("*."):
            t["type"] = "wildcard_domain"
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
            target_value=_stored_target(t["type"], t["value"])))
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


# ─────────────────────── scan levels and asset requests ───────────────────────
#
# Declaring an asset asks a question; it never answers it. The three levels are
# bundles of capabilities, in the order the operator is allowed to widen them:
# a level is only ever as strong as the capabilities it lists, and the engine
# still decides per capability.
#
# The requests below are grants with `status="requested"`, which `authorize`
# ignores by construction. Approving one is the only way a declaration turns
# into authority, and it happens in Grants — never on the declaration screen.

COLLECTOR_PRINCIPAL = "collector"

SCAN_LEVELS: dict[str, dict] = {
    "simple": {
        "label": "basic scan",
        "capabilities": ["passive_discovery", "active_verification"],
        "collects": ("IP addresses, the certificate served (issuer, validity, expiry) "
                     "and the technologies the response reveals"),
        "risk": "opens a TLS connection and reads what the server answers. Nothing else is touched.",
    },
    "advanced": {
        "label": "advanced scan",
        "capabilities": ["passive_discovery", "active_verification",
                         "vulnerability_analysis"],
        "collects": ("everything basic does, plus open ports, the services behind them "
                     "and their versions"),
        "risk": "active but non-intrusive: banners, headers and ports are read; nothing is exploited.",
    },
    "redteam": {
        "label": "deep recon",
        "capabilities": ["passive_discovery", "active_verification",
                         "vulnerability_analysis", "intrusive_testing"],
        "collects": ("everything advanced does, plus content discovery: the paths and "
                     "files a host exposes"),
        "risk": ("sends a larger volume of requests than a basic scan, including to "
                 "paths that do not exist. It still never tests a vulnerability."),
    },
}
SCAN_LEVEL_ORDER = ["simple", "advanced", "redteam"]

# Second-level labels under a country code: the zone of `x.com.ar` is `x.com.ar`,
# not `com.ar`. Small on purpose — guessing zones is how a wildcard ends up
# covering a registrar.
_ZONE_SLDS = {"co", "com", "net", "org", "gob", "edu", "gov", "mil", "art"}


def capabilities_for_level(level: str) -> list[str]:
    entry = SCAN_LEVELS.get(level)
    if entry is None:
        raise ValueError(f"unknown scan level {level!r}; "
                         f"expected one of {sorted(SCAN_LEVELS)}")
    return list(entry["capabilities"])


def level_for_capabilities(capabilities) -> str | None:
    """The widest level fully contained in this capability set, if any."""
    wanted = {c.strip() for c in capabilities if c}
    best = None
    for level in SCAN_LEVEL_ORDER:
        if set(SCAN_LEVELS[level]["capabilities"]) <= wanted:
            best = level
    return best


def _labels(host: str) -> list[str]:
    return [label for label in host.split(".") if label]


def zone_of(host: str) -> str:
    labels = _labels(host)
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels) >= 3 and labels[-2] in _ZONE_SLDS and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def parent_of(host: str) -> str | None:
    labels = _labels(host)
    if len(labels) <= 2:
        return None
    return ".".join(labels[1:])


def _hostname_shaped(value: str) -> bool:
    labels = _labels(value)
    return (len(labels) >= 2 and "/" not in value and ":" not in value
            and all(label.replace("-", "").isalnum() for label in labels)
            and not value.replace(".", "").isdigit())


def _common_suffix(values: list[str]) -> str:
    """Longest label-aligned suffix shared by every value."""
    split = [_labels(value) for value in values]
    suffix: list[str] = []
    for column in range(1, min(len(parts) for parts in split) + 1):
        label = split[0][-column]
        if all(parts[-column] == label for parts in split):
            suffix.insert(0, label)
        else:
            break
    return ".".join(suffix)


def _boundary(values: list[str]) -> str:
    """The host the operator would mean by "this and everything under it".

    For one host that is its parent (`dev.api.example` → `api.example`); for a
    set it is the common ancestor, because widening to a sibling's parent is the
    only widening that stays inside the declaration. Never the zone: that is a
    separate, deliberate choice (`scope="zone"`).
    """
    if not values:
        return ""
    common = _common_suffix(values)
    if common and (len(values) > 1 or common in values):
        if len(values) == 1:
            return parent_of(common) or common
        return common
    return common


def _targets_for(boundary: str) -> list[dict]:
    if not boundary:
        return []
    targets = [{"type": "domain", "value": boundary},
               {"type": "wildcard_domain", "value": f"*.{boundary}"}]
    return targets


def scope_options(values: list[str]) -> list[dict]:
    """The three scopes an approver may choose, with the exact targets each one
    writes. Computed here so the console cannot invent a fourth meaning of
    "everything under it" — and so the apex is never silently left out:
    `*.base` does not cover `base`, so a subtree is always apex + pattern.
    """
    cleaned = [str(value).strip().lower().rstrip(".") for value in values if str(value).strip()]
    cleaned = [value for value in cleaned if value]
    if not cleaned:
        return []
    exact = [{"type": "domain", "value": value} for value in cleaned]
    options = [{
        "scope": "exact",
        "label": (f"{cleaned[0]} only" if len(cleaned) == 1
                  else f"these {len(cleaned)} domains only"),
        "targets": exact,
    }]
    if not all(_hostname_shaped(value) for value in cleaned):
        return options
    boundary = _boundary(cleaned)
    seen = {tuple(sorted((target["type"], target["value"]) for target in exact))}
    for scope, host in (("subtree", boundary), ("zone", zone_of(cleaned[0]))):
        targets = _targets_for(host)
        if not targets:
            continue
        key = tuple(sorted((target["type"], target["value"]) for target in targets))
        if key in seen:
            continue
        seen.add(key)
        if scope == "subtree":
            label = f"{host} and everything under it"
        else:
            label = f"the whole zone: {host} and everything under it"
        options.append({"scope": scope, "label": label, "targets": targets})
    return options


def coverage(session, org_id: str, level: str, targets: list[dict],
             principal: str = COLLECTOR_PRINCIPAL) -> dict:
    """Whether an active grant already covers this level for these targets.

    Delegates every answer to `authorize`, so exclusions, wildcard strictness and
    expiry behave exactly as they do for a collector. A covered asset is declared
    without asking anybody; an uncovered one asks.
    """
    capabilities = capabilities_for_level(level)
    missing: list[str] = []
    exclusion: str | None = None
    for capability in capabilities:
        outcome = authorize(session, org_id, principal, capability, targets)
        if outcome["decision"] == "allow":
            continue
        missing.append(capability)
        if exclusion is None and "exclusion" in outcome.get("reason", ""):
            exclusion = outcome["reason"]
    return {"level": level, "capabilities": capabilities, "covered": not missing,
            "missing": missing, "excluded": exclusion is not None,
            "reason": exclusion or ("" if not missing else
                                    "no active grant covers " + ", ".join(missing))}


def target_for_asset(asset: models.Asset) -> dict:
    kind = asset.type if asset.type in GRANT_TARGET_TYPES else "domain"
    return {"type": kind, "value": str(asset.value).strip().lower()}


def request_grant(session, org_id: str, asset: models.Asset, actor: str,
                  level: str = "simple", targets: list[dict] | None = None,
                  justification: str | None = None) -> tuple[models.ScanGrant, bool]:
    """Open (or reuse) the authorization request for a declared asset.

    Idempotent per asset: declaring the same domain twice does not queue two
    questions. The row is inert until an administrator approves it.
    """
    capabilities = capabilities_for_level(level)
    proposed = targets or [target_for_asset(asset)]
    normalised: list[dict] = []
    for target in proposed:
        kind = target.get("type") or "domain"
        value = _stored_target(kind, str(target.get("value") or ""))
        if not value:
            continue
        if kind == "domain" and value.lower().startswith("*."):
            kind = "wildcard_domain"
        if kind not in GRANT_TARGET_TYPES:
            raise ValueError(f"unknown target type {kind!r}")
        normalised.append({"type": kind, "value": value})
    if not normalised:
        raise ValueError("a request needs at least one target")

    existing = (session.query(models.ScanGrant)
                .filter_by(org_id=org_id, asset_id=asset.id, status="requested")
                .order_by(models.ScanGrant.created_at.desc()).first())
    if existing is not None:
        return existing, False

    now = _now()
    grant = models.ScanGrant(
        org_id=org_id, principal=COLLECTOR_PRINCIPAL,
        capabilities=",".join(capabilities), level=level,
        issued_by=actor, requested_by=actor,
        justification=(justification or
                       f"declared with {asset.type} {asset.value}: "
                       f"ask for a {SCAN_LEVELS[level]['label']}"),
        policy_version=POLICY_VERSION, status="requested",
        asset_id=asset.id, source="asset",
        valid_from=now, valid_until=now + datetime.timedelta(days=7),
        created_at=now, updated_at=now)
    session.add(grant)
    session.flush()
    # Append through the relationship, not the session: the caller reads
    # `grant.targets` in the same breath, and a collection that was loaded empty
    # would answer with the question unanswered.
    for target in normalised:
        grant.targets.append(models.ScanGrantTarget(
            target_type=target["type"], target_value=target["value"]))
    return grant, True


def ensure_authorization(session, org_id: str, asset: models.Asset, actor: str,
                         level: str = "simple") -> dict:
    """The one call both declaration paths make.

    Covered → nothing is asked. Excluded → nothing is asked either, because a
    request that an exclusion will always refuse is a lie. Otherwise a request
    is opened (or the pending one returned).
    """
    target = target_for_asset(asset)
    state = coverage(session, org_id, level, [target])
    if state["covered"]:
        return {"covered": True, "excluded": False, "level": level,
                "request": None, "missing": []}
    if state["excluded"]:
        return {"covered": False, "excluded": True, "level": level,
                "request": None, "missing": state["missing"],
                "reason": state["reason"]}
    grant, created = request_grant(session, org_id, asset, actor, level=level)
    return {"covered": False, "excluded": False, "level": level,
            "request": _grant_summary(grant), "request_created": created,
            "missing": state["missing"]}


def _grant_summary(grant: models.ScanGrant) -> dict:
    return {"id": grant.id, "status": grant.status, "level": grant.level,
            "principal": grant.principal,
            "targets": [{"type": t.target_type, "value": t.target_value}
                        for t in grant.targets]}


def approve_grant(session, grant: models.ScanGrant, actor: str, *,
                  level: str | None = None,
                  capabilities: list[str] | None = None,
                  targets: list[dict] | None = None,
                  hours: int | None = None,
                  environment: str | None = None,
                  justification: str | None = None) -> models.ScanGrant:
    """Turn a request into authority, keeping whatever the approver changed.

    A self-approval is allowed (a one-admin organization must be able to work)
    but it is never silent: `approved_by` records the same identity and the
    caller writes "self-approved" into the audit detail.
    """
    if grant.status not in {"requested", "rejected"}:
        raise ValueError(f"grant {grant.id} is {grant.status}; only a pending "
                         "request can be approved")
    if level is not None:
        capabilities = capabilities_for_level(level)
        grant.level = level
    if capabilities:
        grant.capabilities = ",".join(capabilities)
        grant.level = level_for_capabilities(capabilities) or grant.level
    if targets is not None:
        clean: list[dict] = []
        for target in targets:
            kind = target.get("type") or "domain"
            value = _stored_target(kind, str(target.get("value") or ""))
            if not value:
                continue
            if kind == "domain" and value.lower().startswith("*."):
                kind = "wildcard_domain"
            if kind not in GRANT_TARGET_TYPES:
                raise ValueError(f"unknown target type {kind!r}")
            clean.append({"type": kind, "value": value})
        if not clean:
            raise ValueError("a grant needs at least one target")
        session.execute(sa_delete(models.ScanGrantTarget).where(
            models.ScanGrantTarget.grant_id == grant.id))
        session.expire(grant, ["targets"])
        for target in clean:
            grant.targets.append(models.ScanGrantTarget(
                target_type=target["type"], target_value=target["value"]))
    now = _now()
    grant.status = "active"
    grant.approved_by = actor
    grant.rejection_reason = None
    grant.valid_from = now
    grant.valid_until = now + datetime.timedelta(
        hours=hours if hours is not None else 720)
    if environment is not None:
        grant.environment = environment or None
    if justification:
        grant.justification = justification
    grant.policy_version = POLICY_VERSION
    grant.updated_at = now
    session.flush()
    return grant


def reject_grant(session, grant: models.ScanGrant, actor: str, reason: str) -> None:
    if grant.status != "requested":
        raise ValueError(f"grant {grant.id} is {grant.status}; only a pending "
                         "request can be rejected")
    grant.status = "rejected"
    grant.approved_by = actor
    grant.rejection_reason = reason
    grant.updated_at = _now()


def sync_scope_target(session, org_id: str, grant: models.ScanGrant,
                      actor: str) -> list[str]:
    """Materialise an approved grant into the scope registry.

    Scope is not a second form: it is what the approvals add up to. Every target
    of the grant lands as a `scope_targets` row with `source="grant"`, so the
    Scope screen reads as "what is in scope, and because of which grant" instead
    of a list somebody typed twice.
    """
    written: list[str] = []
    for target in grant.targets:
        kind = target.target_type
        value = target.target_value
        if kind == "wildcard_domain":
            kind, value = "domain", value if value.startswith("*.") else f"*.{value}"
        existing = (session.query(models.ScopeTarget)
                    .filter_by(org_id=org_id, target_type=kind, value=value)
                    .one_or_none())
        include_apex = target.target_type == "wildcard_domain"
        if existing is None:
            session.add(models.ScopeTarget(
                org_id=org_id, target_type=kind, value=value,
                status="active", source="grant", owner=actor,
                note=f"approved grant {grant.id[:8]}",
                capabilities=list(authorization_capabilities(grant)),
                include_apex=include_apex, asset_id=grant.asset_id,
                created_at=_now(), updated_at=_now()))
            written.append(f"{kind}:{value}")
            continue
        existing.status = "active"
        existing.source = existing.source or "grant"
        existing.capabilities = list(authorization_capabilities(grant))
        existing.include_apex = bool(existing.include_apex or include_apex)
        existing.updated_at = _now()
        written.append(f"{kind}:{value}")
    return written


def authorization_capabilities(grant: models.ScanGrant) -> set[str]:
    return {c.strip() for c in grant.capabilities.split(",") if c.strip()}


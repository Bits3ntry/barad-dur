"""Scope semantics: one place that decides what a target value means.

The rules are deliberately narrow and are pinned by tests, because "in scope"
is the only thing standing between an inventory and an intrusive test.

Vocabulary
----------
Types (`SCOPE_TYPES`):
  domain        exact hostname, or a `*.` pattern
  host          hostname, IP literal or CIDR (legacy type kept for compatibility)
  ip            IP literal
  cidr          network in CIDR form
  url           origin plus optional path prefix
  repository    `owner/name` reference to code, never a network target
  service       declarative service name (no network semantics by itself)
  api           declarative API name (no network semantics by itself)
  cloud_account provider account reference; authorizes nothing on its own

Wildcards (`*.example.com`)
---------------------------
A pattern matches **subdomains at any depth** (`api.example.com`,
`a.b.example.com`) and does **not** match the apex `example.com` unless the
target sets `include_apex=True`. The pattern is a rule/seed: it never creates a
host, never expands into names, and never appears in the inventory. Only a
concrete value (exact domain, IP, CIDR, URL) can be linked to an asset.

URLs
----
`https://api.example.com/v1` covers that scheme, that host and that path prefix
(`/v1`, `/v1/x`), not `/v10` and not another scheme or port. A URL target whose
host is itself a `*.` pattern may use a wildcard host.

CIDRs
-----
Matching is containment (.25 matches 10.0.0.0/8); values are normalized with
`ip_network(strict=False)` so `10.1.2.3/8` becomes `10.0.0.0/8`. An IP literal is
not widened to a /32 rule by accident: `ip` only matches the exact address.

Capabilities
------------
`CAPABILITIES` names what an authorization may later permit. Recording them on
the scope row never runs anything; `scan_grants` remain the thing a collector
checks. `cloud_account` rows accept no capability at all, and active
capabilities are never implied — they must be listed explicitly.
"""
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

SCOPE_TYPES = {
    "domain", "host", "ip", "cidr", "url", "repository", "service", "api",
    "cloud_account",
}

CAPABILITIES = {
    "passive_discovery",   # DNS / CT / certificate reading
    "active_verification", # touching the target (TLS probe, HTTP request)
    "code_analysis",       # reading code that belongs to the organization
}

# Types whose concrete value is a resource the inventory can hold.
ASSET_TYPES_BY_SCOPE = {
    "domain": "domain",
    "host": "domain",
    "ip": "ip",
    "cidr": "cidr",
    "url": "url",
}

NETWORK_TYPES = {"domain", "host", "ip", "cidr", "url"}
DECLARATIVE_TYPES = {"repository", "service", "api", "cloud_account"}

DEFAULT_CAPABILITIES = {
    "domain": ["passive_discovery"],
    "host": ["passive_discovery"],
    "ip": ["passive_discovery"],
    "cidr": ["passive_discovery"],
    "url": ["passive_discovery"],
    "repository": ["code_analysis"],
    "service": ["passive_discovery"],
    "api": ["passive_discovery"],
    "cloud_account": [],
}

_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


class ScopeValueError(ValueError):
    """The value does not mean anything for the declared type."""


@dataclass(frozen=True)
class Normalized:
    target_type: str
    value: str            # canonical form stored in the database
    pattern: bool = False # wildcard domain
    host: str | None = None
    include_apex: bool = False
    scheme: str | None = None
    port: int | None = None
    path: str = ""
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    address: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    asset_type: str | None = None


def normalize(target_type: str, value: str, include_apex: bool = False) -> Normalized:
    """Canonicalize a scope value, or raise ScopeValueError explaining why not."""
    if target_type not in SCOPE_TYPES:
        raise ScopeValueError(f"target_type must be one of {sorted(SCOPE_TYPES)}")
    raw = (value or "").strip()
    if not raw:
        raise ScopeValueError("value is required")

    if target_type in {"domain", "host"}:
        return _normalize_domain_like(raw, target_type, include_apex)
    if target_type == "ip":
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            raise ScopeValueError("ip must be an IPv4 or IPv6 address") from None
        return Normalized("ip", str(address), address=address, asset_type="ip")
    if target_type == "cidr":
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            raise ScopeValueError("cidr must be a network such as 10.0.0.0/8") from None
        return Normalized("cidr", str(network), network=network, asset_type="cidr")
    if target_type == "url":
        return _normalize_url(raw)
    if target_type == "repository":
        if not re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", raw):
            raise ScopeValueError("repository must be owner/name")
        return Normalized("repository", raw)
    if target_type in {"service", "api"}:
        return Normalized(target_type, raw)
    return Normalized("cloud_account", raw)


def _normalize_domain_like(raw: str, target_type: str, include_apex: bool) -> Normalized:
    value = raw.lower().rstrip(".")
    if value.startswith("*."):
        base = value[2:]
        if not _HOSTNAME.match(base):
            raise ScopeValueError("wildcard must look like *.example.com")
        return Normalized(target_type, f"*.{base}", pattern=True, host=base,
                          include_apex=include_apex, asset_type=None)
    # A host row may still be an IP or CIDR (legacy rows declared them that way).
    try:
        address = ipaddress.ip_address(value)
        return Normalized(target_type, str(address), address=address, asset_type="ip")
    except ValueError:
        pass
    if "/" in value:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise ScopeValueError("use the url type for a value with a scheme or path") from None
        return Normalized(target_type, str(network), network=network, asset_type="cidr")
    if "://" in value or ":" in value or not _HOSTNAME.match(value):
        raise ScopeValueError("value is not a hostname, IP or CIDR")
    return Normalized(target_type, value, host=value,
                      asset_type=ASSET_TYPES_BY_SCOPE[target_type])


def _normalize_url(raw: str) -> Normalized:
    match = re.match(r"^(?P<scheme>https?)://(?P<host>[^/:?#]+)(?::(?P<port>\d+))?"
                     r"(?P<path>/[^?#]*)?(?P<rest>[?#].*)?$", raw, re.IGNORECASE)
    if not match:
        raise ScopeValueError("url must be http(s)://host[/path] with no query or fragment")
    if match.group("rest"):
        raise ScopeValueError("url scope covers a path prefix; drop the query and fragment")
    host = match.group("host").lower().rstrip(".")
    pattern = host.startswith("*.")
    base = host[2:] if pattern else host
    if not pattern and not _HOSTNAME.match(base):
        raise ScopeValueError("url host is not a hostname")
    if pattern and not _HOSTNAME.match(base):
        raise ScopeValueError("wildcard url host must look like *.example.com")
    path = (match.group("path") or "").rstrip("/")
    port = int(match.group("port")) if match.group("port") else None
    value = f"{match.group('scheme').lower()}://{host}"
    if port:
        value += f":{port}"
    value += path
    return Normalized("url", value, pattern=pattern, host=base,
                      scheme=match.group("scheme").lower(), port=port, path=path,
                      asset_type="url")


def concrete_asset(norm: Normalized) -> tuple[str, str] | None:
    """(asset type, canonical value) when the target is a concrete resource.

    Wildcards return None: a rule is not a host, and inventing one would put a
    fictional name in the inventory.
    """
    if norm.pattern:
        return None
    if norm.asset_type is None:
        return None
    return norm.asset_type, norm.value


def covers(norm: Normalized, target_type: str, value: str) -> bool:
    """Does `norm` cover the concrete value at `target_type`?

    Only concrete values are covered; a wildcard target never covers another
    wildcard (two rules overlapping is a policy question, not a match).
    """
    try:
        other = normalize(target_type, value, norm.include_apex)
    except ScopeValueError:
        return False
    if other.pattern:
        return False

    if norm.target_type in {"domain", "host"}:
        if norm.pattern:
            assert norm.host
            if other.host == norm.host:
                return norm.include_apex
            return bool(other.host and other.host.endswith("." + norm.host))
        if norm.host is not None and other.host is not None:
            return norm.host == other.host
        if norm.address is not None:
            return other.address == norm.address
        if norm.network is not None:
            if other.address is not None:
                return other.address in norm.network
            if other.network is not None:
                return other.network.subnet_of(norm.network)
        return False

    if norm.target_type == "ip":
        return other.address is not None and norm.address == other.address

    if norm.target_type == "cidr":
        if norm.network is None:
            return False
        if other.address is not None:
            return other.address in norm.network
        if other.network is not None:
            return other.network.subnet_of(norm.network)
        return False

    if norm.target_type == "url":
        if other.scheme != norm.scheme:
            return False
        if norm.port is not None and other.port != norm.port:
            return False
        if norm.pattern:
            assert norm.host
            host_ok = bool(other.host and (other.host == norm.host
                                           or other.host.endswith("." + norm.host)))
        else:
            host_ok = other.host == norm.host
        if not host_ok:
            return False
        return other.path == norm.path or other.path.startswith(norm.path + "/")

    # Declarative types match themselves only.
    return norm.target_type == other.target_type and norm.value == other.value


def effective_capabilities(target_type: str, capabilities) -> list[str]:
    """Validate/derived capability list. Never widens beyond what was declared."""
    if capabilities is None:
        return list(DEFAULT_CAPABILITIES.get(target_type, []))
    cleaned = []
    for capability in capabilities:
        if capability not in CAPABILITIES:
            raise ScopeValueError(f"capability must be one of {sorted(CAPABILITIES)}")
        if capability not in cleaned:
            cleaned.append(capability)
    if target_type == "cloud_account" and cleaned:
        raise ScopeValueError(
            "a cloud account reference authorizes nothing; declare concrete targets instead")
    return cleaned


@dataclass
class Decision:
    allowed: bool
    reason: str
    matched_rule: dict | None = None
    excluded_by: dict | None = None
    capabilities: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"allowed": self.allowed, "reason": self.reason,
                "matched_rule": self.matched_rule, "excluded_by": self.excluded_by,
                "capabilities": self.capabilities}


def decide(targets: list, exclusions: list, target_type: str, value: str,
           capability: str | None = None) -> Decision:
    """Evaluate one concrete value: exclusions first, then active targets.

    `targets`/`exclusions` are model rows (duck-typed: target_type, value,
    status, include_apex, valid_until, capabilities). An exclusion that matches
    wins outright; absence of a matching active rule denies.
    """
    if capability is not None and capability not in CAPABILITIES:
        raise ScopeValueError(f"capability must be one of {sorted(CAPABILITIES)}")
    now = _utcnow()
    for row in exclusions:
        if getattr(row, "status", "active") != "active":
            continue
        if not _row_covers(row, target_type, value):
            continue
        expires = _aware(getattr(row, "expires_at", None))
        if expires is not None and expires <= now:
            continue
        return Decision(False, "excluded by an explicit scope exclusion",
                        excluded_by={"id": row.id, "value": row.value,
                                     "reason": getattr(row, "reason", None)})
    for row in targets:
        if getattr(row, "status", "active") != "active":
            continue
        valid_until = _aware(getattr(row, "valid_until", None))
        if valid_until is not None and valid_until <= now:
            continue
        valid_from = _aware(getattr(row, "valid_from", None))
        if valid_from is not None and valid_from > now:
            continue
        if not _row_covers(row, target_type, value):
            continue
        granted = list(getattr(row, "capabilities", None) or [])
        if capability is not None and capability not in granted:
            continue
        return Decision(True, "covered by an active scope target",
                        matched_rule={"id": row.id, "type": row.target_type,
                                      "value": row.value},
                        capabilities=granted)
    return Decision(False, "no active scope target covers this value")


def _row_covers(row, target_type: str, value: str) -> bool:
    try:
        norm = normalize(row.target_type, row.value,
                         bool(getattr(row, "include_apex", False)))
    except ScopeValueError:
        return False
    return covers(norm, target_type, value)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    """SQLite hands back naive datetimes; comparing them to UTC raises."""
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)

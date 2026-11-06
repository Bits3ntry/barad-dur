"""Runtime CVEs: the half OSV cannot answer.

A language runtime is not a package. `pkg:generic/node` has no OSV ecosystem, so
the daily clock counted it as `unmapped` and a frontend built on Node 22 showed
zero risk for the interpreter it runs — while NVD has carried CVEs for that
product for years.

This module closes that gap with the only public data that describes a runtime
by *version range*: NVD's CPE configurations. One request per product returns
every CVE NVD knows with the `cpeMatch` entries that say which versions are
affected; matching is local, so a sweep costs four requests and no guessing.

What it refuses to do:

* invent a version. A declared range (`>=22.12.0 <23`) or a major-only image tag
  (`node:22-alpine`) is matched as an *interval*, and the finding says so —
  "affects a version inside your declared range" is a different claim from
  "affects 22.14.0", and both are more useful than silence.
* claim a fix. NVD has a range, not a released patch; the recommendation quotes
  the range instead of pretending to know the upgrade target.
* touch the artifact. These findings are the clock's, with `source="nvd"`.
"""
from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request

from backend.app import lifecycle, models, vulns

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "barad-dur-platform"

# runtime name → (vendor, product) in the NVD CPE dictionary. Only products with
# one unambiguous CPE: Java's `oracle:jre` covers several distributions and has
# produced false positives, so it stays out until it is mapped on purpose.
PRODUCTS = {
    "node": ("nodejs", "node.js"),
    "python": ("python", "python"),
    "go": ("golang", "go"),
    "php": ("php", "php"),
    "ruby": ("ruby", "ruby"),
    "rust": ("rust-lang", "rust"),
}

# Base image name → runtime, for `pkg:docker/<image>@<tag>` rows.
IMAGES = {
    "node": "node",
    "python": "python",
    "golang": "go",
    "ruby": "ruby",
    "php": "php",
    "rust": "rust",
}

CONFIDENCE_TEXT = {
    "exact": "the pinned version is affected",
    "range": "a version inside the declared range is affected",
    # A floating image tag names a line, not a patch: `3.11-slim` today pulls the
    # newest 3.11.x, and NVD cannot say which one. Saying "line" keeps the claim
    # from pretending to know the digest.
    "line": "a version in this line is affected — NVD has a range, not your patch level",
}

_EXACT = re.compile(r"^v?(\d+(?:\.\d+){0,3})(?:[-+][0-9A-Za-z.\-]+)?$")


# ------------------------------------------------------------------ versions

def parse_version(text) -> tuple[int, ...] | None:
    if not isinstance(text, str):
        return None
    match = _EXACT.match(text.strip())
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _cmp(left: tuple, right: tuple) -> int:
    size = max(len(left), len(right))
    a = left + (0,) * (size - len(left))
    b = right + (0,) * (size - len(right))
    return (a > b) - (a < b)


class Interval:
    """[low, high) with inclusive/exclusive flags; None means unbounded."""

    def __init__(self, low=None, low_inclusive=True, high=None, high_inclusive=False):
        self.low, self.low_inclusive = low, low_inclusive
        self.high, self.high_inclusive = high, high_inclusive

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (f"Interval({self.low}{'>=' if self.low_inclusive else '>'}, "
                f"{self.high}{'<=' if self.high_inclusive else '<'})")


def overlaps(left: Interval, right: Interval) -> bool:
    """Whether two ranges share at least one version."""
    if (left.high is not None and right.low is not None):
        order = _cmp(left.high, right.low)
        if order < 0 or (order == 0 and not (left.high_inclusive and right.low_inclusive)):
            return False
    if (right.high is not None and left.low is not None):
        order = _cmp(right.high, left.low)
        if order < 0 or (order == 0 and not (right.high_inclusive and left.low_inclusive)):
            return False
    return True


def declared_interval(version: str | None, tag: bool = False) -> tuple[Interval, str] | None:
    """What the inventory states, as an interval, plus how strong the claim is.

    `22.14.0` is a point, `>=22.12.0 <23` is a range, `22-alpine` is the 22 line.
    The confidence travels with the finding: it is the difference between a fact
    about a version and a fact about a window.
    """
    text = (version or "").strip()
    if not text:
        return None
    if tag:
        # An image tag is not a version. `22.14.0-alpine` pins; `22-alpine` names
        # the 22 line; `3.11-slim` names the 3.11 line. Reading `-slim` as a
        # version suffix would turn "python 3.11" into "python 3" and match every
        # CVE of the whole major line.
        match = re.match(r"^(\d+(?:\.\d+)*)([-+].*)?$", text)
        if not match:
            return None
        parts = tuple(int(part) for part in match.group(1).split("."))
        if len(parts) >= 3:
            return Interval(parts, True, parts, True), "exact"
        if len(parts) == 2:
            return Interval(parts + (0,), True, (parts[0], parts[1] + 1, 0), False), "line"
        return Interval((parts[0], 0, 0), True, (parts[0] + 1, 0, 0), False), "line"
    point = parse_version(text)
    if point is not None:
        return Interval(point, True, point, True), "exact"
    bounds = _parse_spec(text)
    if bounds is not None:
        return bounds, "range"
    major = re.match(r"^(\d+)(?:[-.].*)?$", text)
    if major:
        low = (int(major.group(1)), 0, 0)
        high = (int(major.group(1)) + 1, 0, 0)
        return Interval(low, True, high, False), "major"
    return None


def _parse_spec(spec: str) -> Interval | None:
    """Parse the constraint shapes a manifest actually carries."""
    low = high = None
    low_inclusive = True
    high_inclusive = False
    found = False
    for raw in re.split(r"[,|\s]+", spec.strip()):
        token = raw.strip()
        if not token or token in {"and", "&&", "||"}:
            continue
        match = re.match(r"^(>=|<=|>|<|==|=|\^|~)?\s*v?(\d[0-9A-Za-z.\-+]*)$", token)
        if not match:
            continue
        operator, number = match.group(1) or "==", match.group(2)
        version = parse_version(number)
        if version is None:
            # A tag like `22-alpine` is not a constraint; it is handled as a
            # major line by `declared_interval`, not guessed into a point here.
            continue
        found = True
        if operator in (">=", ">", "^", "~"):
            low, low_inclusive = version, operator == ">="
            if operator == "^" and len(version) >= 1:
                high = (version[0] + 1, 0, 0)
            elif operator == "~" and len(version) >= 2:
                high = (version[0], version[1] + 1, 0)
        elif operator in ("<=", "<"):
            high, high_inclusive = version, operator == "<="
        elif operator in ("==", "="):
            low, low_inclusive = version, True
            high, high_inclusive = version, True
    if not found:
        return None
    return Interval(low, low_inclusive, high, high_inclusive)


# ------------------------------------------------------------------ CPE data

def _cpe_intervals(cve: dict, prefix: str) -> list[Interval]:
    """The version ranges this CVE declares for one product."""
    found: list[Interval] = []
    for configuration in cve.get("configurations") or []:
        for node in configuration.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                criteria = str(match.get("criteria") or "")
                if not criteria.startswith(prefix) or match.get("vulnerable") is False:
                    continue
                start_in = parse_version(match.get("versionStartIncluding"))
                start_ex = parse_version(match.get("versionStartExcluding"))
                end_in = parse_version(match.get("versionEndIncluding"))
                end_ex = parse_version(match.get("versionEndExcluding"))
                if start_in or start_ex or end_in or end_ex:
                    found.append(Interval(low=start_in or start_ex,
                                          low_inclusive=bool(start_in),
                                          high=end_in or end_ex,
                                          high_inclusive=bool(end_in)))
                    continue
                declared = criteria[len(prefix):].split(":", 1)[0]
                if declared in ("*", "-", ""):
                    found.append(Interval())
                elif declared.endswith(".*"):
                    base = tuple(int(part) for part in declared[:-2].split(".") if part.isdigit())
                    if base:
                        found.append(Interval(base, True,
                                              base[:-1] + (base[-1] + 1,), False))
                else:
                    exact = parse_version(declared)
                    if exact:
                        found.append(Interval(exact, True, exact, True))
    return found


def severity_of(cve: dict) -> tuple[str, str | None, float | None]:
    """(severity, vector, score) from the best CVSS the record carries."""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        data = entries[0].get("cvssData") or {}
        severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
        if not severity and key == "cvssMetricV2":
            score = data.get("baseScore")
            severity = ("HIGH" if score and score >= 7 else
                        "MEDIUM" if score and score >= 4 else "LOW")
        if severity:
            return str(severity).upper(), data.get("vectorString"), data.get("baseScore")
    return "UNKNOWN", None, None


def fetch_product(vendor: str, product: str, *, timeout: float = 45.0,
                  api_key: str | None = None) -> list[dict]:
    """Every CVE NVD lists for one product, one page at a time."""
    results: list[dict] = []
    start = 0
    while True:
        query = urllib.parse.urlencode({
            "virtualMatchString": f"cpe:2.3:a:{vendor}:{product}",
            "resultsPerPage": 2000, "startIndex": start})
        request = urllib.request.Request(f"{NVD_URL}?{query}",
                                         headers={"User-Agent": USER_AGENT,
                                                  **({"apiKey": api_key} if api_key else {})})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.load(response)
        batch = payload.get("vulnerabilities") or []
        results.extend(item.get("cve") for item in batch if isinstance(item.get("cve"), dict))
        start += len(batch)
        total = int(payload.get("totalResults") or 0)
        if not batch or start >= total:
            return results


# ------------------------------------------------------------------ analysis

def runtime_of(component) -> tuple[str, str | None] | None:
    """(runtime name, version-or-tag) for a component that *is* a runtime."""
    purl = component.purl or ""
    if purl.startswith("pkg:generic/"):
        name = purl[len("pkg:generic/"):].split("@", 1)[0].split("?", 1)[0].strip("/")
        return (name, component.version) if name else None
    if purl.startswith("pkg:docker/"):
        reference = purl[len("pkg:docker/"):].split("@", 1)[0].split("?", 1)[0]
        image = reference.split("/")[-1].lower()
        runtime = IMAGES.get(image)
        if runtime is None:
            return None
        tag = purl.split("@", 1)[1].split("?", 1)[0] if "@" in purl else component.version
        return runtime, tag
    return None


def analyze(session, org_id: str, project: models.Project,
            project_version: models.ProjectVersion, *, fetch=None,
            cache: dict | None = None, api_key: str | None = None) -> dict:
    """Match this build's runtime components against NVD and record findings.

    Idempotent on `(component, CVE)`: a rerun refreshes the row it already made
    instead of adding a second one, and a CVE the artifact already reported under
    another advisory id refreshes that row too.
    """
    fetch = fetch or (lambda vendor, product: fetch_product(vendor, product, api_key=api_key))
    cache = {} if cache is None else cache
    counters = {"runtimes": 0, "runtimes_matched": 0, "runtimes_skipped": 0,
                "findings_created": 0, "findings_refreshed": 0, "created_ids": [],
                "errors": []}
    rows = (session.query(models.VersionComponent, models.Component)
            .join(models.Component, models.VersionComponent.component_id == models.Component.id)
            .filter(models.VersionComponent.project_version_id == project_version.id).all())
    now = models.utcnow()
    for _link, component in rows:
        parsed = runtime_of(component)
        if parsed is None:
            continue
        counters["runtimes"] += 1
        name, stated = parsed
        product = PRODUCTS.get(name)
        declared = declared_interval(stated,
                                     tag=(component.purl or "").startswith("pkg:docker/"))
        if product is None or declared is None:
            counters["runtimes_skipped"] += 1
            if product is None:
                counters["errors"].append({"source": "nvd", "runtime": name,
                                           "error": "no CPE product mapped for this runtime"})
            continue
        interval, confidence = declared
        key = product
        if key not in cache:
            try:
                cache[key] = fetch(*product)
            except Exception as error:  # noqa: BLE001 — an outage is a fact, not a crash
                counters["errors"].append({"source": "nvd", "product": "/".join(product),
                                           "error": f"{type(error).__name__}: {error}"})
                cache[key] = []
        prefix = f"cpe:2.3:a:{product[0]}:{product[1]}:"
        matched = 0
        for cve in cache[key] or []:
            if not isinstance(cve, dict) or not cve.get("id"):
                continue
            if not any(overlaps(interval, item) for item in _cpe_intervals(cve, prefix)):
                continue
            matched += 1
            _record(session, org_id, project, project_version, component, cve,
                    confidence, now, counters)
        if matched:
            counters["runtimes_matched"] += 1
    return counters


def _record(session, org_id, project, project_version, component, cve,
            confidence, now, counters) -> None:
    severity, vector, score = severity_of(cve)
    description = next((item.get("value") for item in cve.get("descriptions") or []
                        if item.get("lang") == "en"), None) or cve["id"]
    title = f"{cve['id']}: {description}"[:400]
    advisory = session.query(models.Vulnerability).filter_by(source_id=cve["id"]).one_or_none()
    if advisory is None:
        advisory = models.Vulnerability(source_id=cve["id"], source="nvd", cve_id=cve["id"],
                                        title=title, severity=severity,
                                        cvss_vector=vector, url=f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
                                        fetched_at=now)
        session.add(advisory)
        session.flush()
    else:
        advisory.title = title
        advisory.severity = severity
        advisory.cvss_vector = vector
        advisory.fetched_at = now
    fingerprint = vulns.vulnerability_fingerprint(org_id, project.id,
                                                  component.identity_key, advisory.source_id)
    finding = (session.query(models.Finding).filter_by(org_id=org_id,
                                                      fingerprint=fingerprint).one_or_none())
    if finding is None:
        finding = vulns.finding_for_cve(session, org_id, project.id, component.id, cve["id"])
    note = f"NVD {cve['id']} on {component.name or 'runtime'} {component.version or ''}: {CONFIDENCE_TEXT[confidence]}."
    if finding is None:
        finding = models.Finding(
            org_id=org_id, project_id=project.id, kind="vulnerability",
            vector="runtime-cve", fingerprint=fingerprint, source="nvd",
            title=title, severity=severity, url=advisory.url,
            detail=json.dumps({"advisory": cve["id"], "confidence": confidence,
                               "cvss": score, "vector": vector,
                               "runtime": component.name,
                               "declared": component.version}, sort_keys=True),
            tool="nvd-cpe", rule_id=cve["id"], component_id=component.id,
            vulnerability_id=advisory.id, last_seen_version_id=project_version.id,
            recommendation=(f"NVD marks every version in that range affected; upgrade the "
                            f"{component.name} runtime past it and check the vendor's releases"),
            first_seen_at=now, last_seen_at=now, updated_at=now)
        session.add(finding)
        session.flush()
        lifecycle.apply_lifecycle(session, org_id, finding)
        counters["findings_created"] += 1
        counters["created_ids"].append(finding.id)
    else:
        finding.last_seen_at = now
        finding.last_seen_version_id = project_version.id
        finding.severity = severity
        finding.title = title
        finding.detail = note
        finding.updated_at = now
        counters["findings_refreshed"] += 1

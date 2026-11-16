"""The KEV catalogues: more than one publisher says a CVE is being exploited.

CISA's catalog is the reference — it is what "KEV" means to a reader, and the only
one of the three that publishes a remediation deadline. It is not the whole world:
the EU list (ENISA's curated CNW feed, one row per known-exploited CVE with the
report behind it) carries rows CISA never added, and VulnCheck's catalog is wider
still and often earlier. Mirroring one of them answers "what is CISA saying"; the
question the console asks is "what is the world saying".

The mirror stays **one row per CVE** — `kev_entries.cve_id` is the key every other
screen joins on (the matched estate, EPSS, priority rules, the advisory resolver) —
so merging is this module's job, not stacking:

* CISA is authoritative: when it lists the CVE, its text, its dates and its due
  date win, and they may overwrite what another source wrote.
* Every other source only fills gaps (a description CISA lacks, the EUVD id, the
  exploitation type, the evidence behind the claim) and adds its slug to
  `sources`, which is what the console shows as *who says so*.
* A source that fails is reported, never fatal: an EU outage must not empty the
  catalogue CISA just refreshed, and a missing API token is a state, not an error.

Adding a catalogue is one `KevSource` entry below. Nothing else knows how many
there are: the sync loops over the tuple and the screen renders whatever the
registry reports. `KEV_SOURCES` (comma-separated slugs) narrows the set for a
deployment that cannot reach one of them.
"""
from __future__ import annotations

import datetime
import json
import os
import urllib.request

from backend.app import models

CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EU_URL = "https://raw.githubusercontent.com/enisaeu/CNW/main/advisories/eukev/eukev.json"
VULNCHECK_URL = "https://api.vulncheck.com/v3/backup/vulncheck-kev"

CISA = "cisa-kev"
VULNCHECK = "vulncheck-kev"
EU = "eu-kev"

# Authority order. `sources` is stored in this order so the column reads
# "cisa-kev,eu-kev" and not whatever order the network answered in.
SOURCE_ORDER = (CISA, VULNCHECK, EU)

USER_AGENT = "barad-dur-platform"
_MAX_PAGES = 40


class MissingCredentials(Exception):
    """The catalogue exists but needs a token this deployment has not set."""

    def __init__(self, env_name: str):
        self.env_name = env_name
        super().__init__(f"{env_name} is not set")


class KevSource:
    """One catalogue: where it lives, what it costs to read, how to parse it."""

    def __init__(self, slug: str, label: str, url: str, fetch, token_env: str | None = None):
        self.slug = slug
        self.label = label
        self.url = url
        self.fetch = fetch
        self.token_env = token_env

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<KevSource {self.slug}>"


# ── shared helpers ───────────────────────────────────────────────────────────

def _iso(value) -> str | None:
    """Feed dates arrive as `2026-08-10`, `2026/08/10` and full timestamps.

    One column holds them all, so they are normalised to `YYYY-MM-DD` here; a
    date the parser cannot read becomes None instead of a string that sorts
    wrongly against every other row.
    """
    if value is None:
        return None
    text = str(value).strip().replace("/", "-")
    if len(text) < 10:
        return None
    try:
        return datetime.date.fromisoformat(text[:10]).isoformat()
    except ValueError:
        return None


def _join(values) -> str | None:
    if isinstance(values, str):
        values = [values]
    items = [str(item).strip() for item in (values or []) if str(item).strip()]
    return ", ".join(items) or None


def _get(url: str, headers: dict | None = None, timeout: float = 25.0):
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/json",
                      **(headers or {})})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read()
    return json.loads(body or b"{}")


def _token(source: KevSource) -> str | None:
    if not source.token_env:
        return None
    return os.environ.get(source.token_env) or None


# ── CISA ─────────────────────────────────────────────────────────────────────

def _parse_cisa(payload) -> list[dict]:
    """The reference catalogue. The feed's own field names, no guessing.

    `title` does not exist in the feed: reading it left all 1769 rows with a null
    name, which made the mirror a list of ids with nothing to search.
    """
    rows = []
    for entry in payload.get("vulnerabilities", []):
        rows.append({
            "cve_id": entry.get("cveID"),
            "title": entry.get("vulnerabilityName"),
            "name": entry.get("vulnerabilityName"),
            "vendor": entry.get("vendorProject"),
            "product": entry.get("product"),
            "description": entry.get("shortDescription"),
            "required_action": entry.get("requiredAction"),
            "ransomware": entry.get("knownRansomwareCampaignUse"),
            "cwes": _join(entry.get("cwes")),
            "date_added": _iso(entry.get("dateAdded")),
            "due_date": _iso(entry.get("dueDate")),
            "notes": entry.get("notes"),
            "source": CISA,
        })
    return [row for row in rows if row["cve_id"]]


def _fetch_cisa(timeout: float = 25.0) -> list[dict]:
    return _parse_cisa(_get(CISA_URL, timeout=timeout))


# ── EU KEV (ENISA CNW) ───────────────────────────────────────────────────────

def _parse_eu(payload) -> list[dict]:
    """The EU list: curated, terse, and the only one that says *why* it is listed.

    Its fields are `cveID`, `euvdID`, `vendorProject`, `product`, `dateReported`,
    `patchedSince`, `originSource`, `shortDescription`, `exploitationType`, `cwes`
    and `notes` (a link to the report of the exploitation). There is no
    `dueDate`: `patchedSince` is when the vendor started shipping a fix, which is
    not a remediation deadline and is not stored as one.
    """
    entries = payload if isinstance(payload, list) else (
        payload.get("vulnerabilities") or payload.get("data") or [])
    rows = []
    for entry in entries:
        exploitation = (entry.get("exploitationType") or "").strip() or None
        rows.append({
            "cve_id": entry.get("cveID") or entry.get("cve"),
            "title": entry.get("vulnerabilityName"),
            "name": entry.get("vulnerabilityName"),
            "vendor": entry.get("vendorProject"),
            "product": entry.get("product"),
            "description": entry.get("shortDescription"),
            "required_action": None,
            # The EU list distinguishes ransomware from APT use; only the former
            # is the claim the CISA field makes.
            "ransomware": "Known" if (exploitation or "").lower() == "ransomware" else None,
            "cwes": _join(entry.get("cwes")),
            # `dateReported` is the date the exploitation was reported, which is
            # the closest thing this list has to CISA's `dateAdded`.
            "date_added": _iso(entry.get("dateReported")),
            "due_date": None,
            "exploitation_type": exploitation,
            "euvd_id": entry.get("euvdID"),
            # Not `notes`: that column holds CISA's reading notes and the two
            # would overwrite each other on every sync.
            "eu_evidence": entry.get("notes"),
            "source": EU,
        })
    return [row for row in rows if row["cve_id"]]


def _fetch_eu(timeout: float = 25.0) -> list[dict]:
    return _parse_eu(_get(EU_URL, timeout=timeout))


# ── VulnCheck KEV ────────────────────────────────────────────────────────────

def _parse_vulncheck(payload) -> list[dict]:
    """VulnCheck KEV: wider than CISA and earlier, but every row costs paging.

    Two traps. `cve` is an **array** — a record can cover several ids, and reading
    it as a string yields one long unusable key. And `required_action` is snake
    case here while CISA spells it `requiredAction`; the row is normalized on the
    way in so the merge does not have to care which catalogue it came from.
    """
    rows = []
    for entry in payload.get("data") or []:
        cves = entry.get("cve") or []
        if isinstance(cves, str):
            cves = [cves]
        for cve in cves:
            if not cve:
                continue
            rows.append({
                "cve_id": cve,
                "title": entry.get("vulnerabilityName"),
                "name": entry.get("vulnerabilityName"),
                "vendor": entry.get("vendorProject"),
                "product": entry.get("product"),
                "description": entry.get("shortDescription"),
                "required_action": entry.get("required_action")
                                    or entry.get("requiredAction"),
                "ransomware": entry.get("knownRansomwareCampaignUse"),
                "cwes": _join(entry.get("cwes")),
                "date_added": _iso(entry.get("date_added")),
                "due_date": _iso(entry.get("dueDate")),
                "source": VULNCHECK,
            })
    return rows


def _fetch_vulncheck(timeout: float = 25.0) -> list[dict]:
    """Page the backup endpoint until it stops handing out a `_next` cursor."""
    token = os.environ.get("VULNCHECK_API_KEY") or os.environ.get("VULNCHECK_TOKEN")
    if not token:
        raise MissingCredentials("VULNCHECK_API_KEY")
    headers = {"Authorization": f"Bearer {token}"}
    rows: list[dict] = []
    url = VULNCHECK_URL
    pages = 0
    while url and pages < _MAX_PAGES:
        payload = _get(url, headers=headers, timeout=timeout)
        rows.extend(_parse_vulncheck(payload))
        url = payload.get("_next") or None
        pages += 1
    return rows


SOURCES: tuple[KevSource, ...] = (
    KevSource(CISA, "CISA KEV", CISA_URL, _fetch_cisa),
    KevSource(VULNCHECK, "VulnCheck KEV", VULNCHECK_URL, _fetch_vulncheck,
              token_env="VULNCHECK_API_KEY"),
    KevSource(EU, "EU KEV", EU_URL, _fetch_eu),
)

BY_SLUG = {source.slug: source for source in SOURCES}


def enabled_sources() -> list[KevSource]:
    """The catalogues this deployment mirrors. `KEV_SOURCES` narrows the set.

    An empty or unreadable value means "all of them": a deployment that filters
    itself down to nothing would look like a broken feed instead of a setting.
    """
    raw = (os.environ.get("KEV_SOURCES") or "").strip()
    if not raw:
        return list(SOURCES)
    wanted = {item.strip().lower() for item in raw.split(",") if item.strip()}
    chosen = [source for source in SOURCES if source.slug in wanted]
    return chosen or list(SOURCES)


# ── merging ──────────────────────────────────────────────────────────────────

def _rank(slug: str) -> int:
    return SOURCE_ORDER.index(slug) if slug in SOURCE_ORDER else len(SOURCE_ORDER)


def merge_sources(current: str | None, slug: str) -> str:
    """Union of the slugs that list a CVE, in authority order."""
    seen = [item for item in (current or "").split(",") if item.strip()]
    if slug and slug not in seen:
        seen.append(slug)
    return ",".join(sorted(seen, key=lambda item: (_rank(item), item)))


def apply(session, rows: list[dict], now=None, source: str | None = None) -> int:
    """Merge feed rows into `kev_entries`. Returns how many rows were touched.

    CISA owns the row: it may overwrite a field another catalogue wrote. Everyone
    else only fills what is empty — filling gaps is useful (the EU list names the
    exploitation type and the EUVD id) while overwriting is how a mirror starts
    disagreeing with itself between two syncs.
    """
    now = now or models.utcnow()
    written = 0
    for raw in rows:
        row = dict(raw)
        slug = row.pop("source", None) or source or "unknown"
        cve_id = row.get("cve_id")
        if not cve_id:
            continue
        authoritative = slug == CISA
        entry = session.get(models.KevEntry, cve_id)
        if entry is None:
            entry = models.KevEntry(cve_id=cve_id, sources=slug, fetched_at=now)
            if authoritative:
                entry.source = slug
            for key, value in row.items():
                if key == "cve_id" or value in (None, "") or not hasattr(entry, key):
                    continue
                setattr(entry, key, value)
            session.add(entry)
            written += 1
            continue
        for key, value in row.items():
            if key == "cve_id" or value in (None, "") or not hasattr(entry, key):
                continue
            if authoritative or not getattr(entry, key):
                setattr(entry, key, value)
        if authoritative or not entry.source:
            entry.source = slug
        entry.sources = merge_sources(entry.sources, slug)
        entry.fetched_at = now
        written += 1
    # The next catalogue's pass must see these rows: sessions here run without
    # autoflush, and an unflushed insert makes the EU pass re-add a CVE CISA just
    # wrote (UNIQUE constraint on cve_id, mid-sync).
    session.flush()
    return written


# ── sync + coverage ──────────────────────────────────────────────────────────

def _state(session, source: KevSource) -> models.KevFeedState:
    row = session.get(models.KevFeedState, source.slug)
    if row is None:
        row = models.KevFeedState(source=source.slug, label=source.label,
                                  url=source.url)
        session.add(row)
        session.flush()
    return row


def sync(session, *, timeout: float = 25.0, fetchers: dict | None = None,
         now=None) -> dict:
    """Fetch every catalogue, merge it, and say how each one answered.

    One source failing is information for the screen, not a reason to abandon the
    others: partial success is the normal state of a feed-driven mirror.
    """
    now = now or models.utcnow()
    fetchers = fetchers or {}
    report: list[dict] = []
    touched: set[str] = set()
    for source in enabled_sources():
        state = _state(session, source)
        override = fetchers.get(source.slug)
        # A caller that hands us its own rows has already solved the credential
        # question; only a real fetch is gated on the token.
        if override is None and source.token_env and not _token(source):
            state.last_error = f"{source.token_env} is not set"
            state.last_error_at = now
            report.append({"source": source.slug, "label": source.label,
                           "ok": False, "skipped": "missing credentials",
                           "rows": 0, "error": state.last_error})
            continue
        fetch = override or (lambda s=source: s.fetch(timeout))
        try:
            rows = fetch()
        except MissingCredentials as error:
            state.last_error = str(error)
            state.last_error_at = now
            report.append({"source": source.slug, "label": source.label,
                           "ok": False, "skipped": "missing credentials",
                           "rows": 0, "error": str(error)})
            continue
        except Exception as error:  # noqa: BLE001 — a feed outage is a fact
            state.last_error = f"{type(error).__name__}: {error}"[:500]
            state.last_error_at = now
            report.append({"source": source.slug, "label": source.label,
                           "ok": False, "rows": 0, "error": state.last_error})
            continue
        written = apply(session, rows, now=now, source=source.slug)
        touched.update(row["cve_id"] for row in rows if row.get("cve_id"))
        state.label = source.label
        state.url = source.url
        state.last_ok_at = now
        state.last_ok_rows = len(rows)
        state.last_error = None
        state.last_error_at = None
        report.append({"source": source.slug, "label": source.label,
                       "ok": True, "rows": len(rows), "written": written})
    session.flush()
    # `rows` is how many CVEs the mirror now holds from this pass, not the sum of
    # the catalogues: a CVE three publishers list is one row on the screen, and a
    # count that says three would make "refreshed" a number the reader cannot find.
    return {"rows": len(touched), "written": sum(item.get("written", 0) for item in report),
            "sources": report}


def coverage(session) -> list[dict]:
    """What each catalogue last said, in registry order.

    Statuses are tokens (`connected`, `never synced`, `credentials missing`,
    `error`), not prose: the screen translates them, and a status that is a
    sentence can only be shown in one language.

    Three counts, because they answer three different questions: `advertised` is
    how big the catalogue says it is, `listed` is how many rows of the mirror it
    put there, and `exclusive` is how many no other publisher lists — the last one
    is the only number that says whether the source is worth its cost.
    """
    stored = {row.source: row for row in
              session.query(models.KevFeedState).all()}
    listed: dict[str, int] = {}
    exclusive: dict[str, int] = {}
    for (sources,) in session.query(models.KevEntry.sources).all():
        slugs = [item for item in (sources or "").split(",") if item.strip()]
        for slug in slugs:
            listed[slug] = listed.get(slug, 0) + 1
        if len(slugs) == 1:
            exclusive[slugs[0]] = exclusive.get(slugs[0], 0) + 1
    out = []
    for source in SOURCES:
        state = stored.get(source.slug)
        item = {"source": source.slug, "label": source.label,
                "url": source.url, "credential": source.token_env,
                "advertised": state.last_ok_rows if state else 0,
                "listed": listed.get(source.slug, 0),
                "exclusive": exclusive.get(source.slug, 0),
                "last_ok_at": (state.last_ok_at.isoformat()
                               if state and state.last_ok_at else None),
                "error": state.last_error if state else None,
                "last_error_at": (state.last_error_at.isoformat()
                                  if state and state.last_error_at else None)}
        if source.token_env and not _token(source):
            item["status"] = "credentials missing"
        elif state is None or state.last_ok_at is None:
            item["status"] = "error" if state and state.last_error else "never synced"
        elif state.last_error:
            item["status"] = "error"
        else:
            item["status"] = "connected"
        out.append(item)
    return out

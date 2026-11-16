"""More than one publisher says a CVE is exploited. The mirror has to merge them.

Three claims this file defends:

* **One row per CVE.** `kev_entries.cve_id` is the join every other screen makes
  (the matched estate, EPSS, priority rules), so a second catalogue adds provenance
  and fills gaps — it does not add a row, and it does not overwrite CISA.
* **The feeds' field names are not guessable.** The EU list has no `requiredAction`
  and no `dueDate`; VulnCheck puts the CVE in an *array* and spells the field
  `required_action`. Reading either with CISA's shape leaves null rows that look
  like an empty catalog rather than a parser bug.
* **A feed that fails is a fact, not a crash.** The EU list being unreachable must
  not empty the mirror CISA just refreshed, and a missing VulnCheck token is a
  state the screen can show — never a 500 and never a silent zero.
"""
import json
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import kev_feeds, models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402
from backend.app.routers import intelligence  # noqa: E402


CISA_PAYLOAD = {"vulnerabilities": [{
    "cveID": "CVE-2026-111497", "vendorProject": "Google", "product": "Brotli",
    "vulnerabilityName": "Google Brotli Unchecked Return Value Vulnerability",
    "shortDescription": "CISA's description.",
    "requiredAction": "Apply mitigations.", "dueDate": "2026-11-10",
    "dateAdded": "2026-10-27", "knownRansomwareCampaignUse": "Unknown",
    "cwes": ["CWE-252", "CWE-787"]}]}

# The same CVE plus one CISA has not listed, in the EU list's own shape.
EU_PAYLOAD = [
    {"cveID": "CVE-2026-111497", "euvdID": "EUVD-2026-51097", "vendorProject": "Google",
     "product": "Brotli", "dateReported": "2026/10/28", "patchedSince": "2026/10/20",
     "originSource": "ENISA", "shortDescription": "The EU list's description.",
     "exploitationType": "APT", "cwes": "CWE-252",
     "notes": "https://example.test/exploited"},
    {"cveID": "CVE-2026-999999", "euvdID": "EUVD-2026-99999", "vendorProject": "VMware",
     "product": "vCenter", "dateReported": "2026/08/10", "patchedSince": "2026/08/03",
     "originSource": "CERT-PL", "shortDescription": "Directory traversal.",
     "exploitationType": "ransomware", "cwes": "CWE-22", "notes": None},
]

VULNCHECK_PAYLOAD = {"data": [{
    # `cve` is a list: one record can cover several ids.
    "cve": ["CVE-2026-111497", "CVE-2026-777777"],
    "vendorProject": "Google", "product": "Brotli",
    "vulnerabilityName": "VulnCheck name",
    "shortDescription": "VulnCheck description.",
    "required_action": "Apply mitigations per vendor instructions.",
    "knownRansomwareCampaignUse": "Known", "cwes": ["CWE-787"],
    "date_added": "2026-10-01T00:00:00Z", "dueDate": "2026-11-01T00:00:00Z",
    "cisa_date_added": "2026-10-27T00:00:00Z"}]}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/sources.db")
    monkeypatch.setenv("BOOTSTRAP_TOKEN", "boot")
    monkeypatch.delenv("VULNCHECK_API_KEY", raising=False)
    monkeypatch.delenv("KEV_SOURCES", raising=False)
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "kev")
    session.commit()
    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}, session


# ── parsers ──────────────────────────────────────────────────────────────────

def test_the_eu_list_is_read_with_its_own_field_names():
    rows = kev_feeds._parse_eu(EU_PAYLOAD)
    assert [row["cve_id"] for row in rows] == ["CVE-2026-111497", "CVE-2026-999999"]
    first = rows[0]
    assert first["vendor"] == "Google" and first["product"] == "Brotli"
    assert first["description"] == "The EU list's description."
    # `2026/10/28` is not ISO; a raw copy would sort after every ISO date.
    assert first["date_added"] == "2026-10-28"
    assert first["due_date"] is None, "patchedSince is not a remediation deadline"
    assert first["euvd_id"] == "EUVD-2026-51097"
    assert first["exploitation_type"] == "APT"
    assert first["source"] == kev_feeds.EU
    assert first["eu_evidence"] == "https://example.test/exploited"
    # Only the ransomware claim maps onto CISA's column; APT does not.
    assert first["ransomware"] is None
    assert rows[1]["ransomware"] == "Known"


def test_vulncheck_expands_the_cve_array_and_reads_the_snake_case_action():
    rows = kev_feeds._parse_vulncheck(VULNCHECK_PAYLOAD)
    assert [row["cve_id"] for row in rows] == ["CVE-2026-111497", "CVE-2026-777777"]
    assert rows[0]["required_action"].startswith("Apply mitigations")
    assert rows[0]["date_added"] == "2026-10-01", "the timestamp is truncated to a day"
    assert rows[0]["due_date"] == "2026-11-01"
    assert rows[0]["cwes"] == "CWE-787"


def test_cisa_fetch_still_reads_what_the_feed_actually_has(monkeypatch):
    """The legacy name and the shared HTTP path keep working."""
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps(CISA_PAYLOAD).encode()

    monkeypatch.setattr(intelligence.urllib.request, "urlopen",
                        lambda *args, **kwargs: FakeResponse())
    row = intelligence.fetch_kev()[0]
    assert row["name"] == "Google Brotli Unchecked Return Value Vulnerability"
    assert row["source"] == kev_feeds.CISA


# ── merging ──────────────────────────────────────────────────────────────────

def test_the_same_cve_from_three_publishers_is_one_row_with_three_sources(client):
    _, _, session = client
    kev_feeds.apply(session, kev_feeds._parse_cisa(CISA_PAYLOAD))
    kev_feeds.apply(session, kev_feeds._parse_eu(EU_PAYLOAD))
    kev_feeds.apply(session, kev_feeds._parse_vulncheck(VULNCHECK_PAYLOAD))
    session.commit()

    merged = session.query(models.KevEntry).filter_by(cve_id="CVE-2026-111497").one()
    assert session.query(models.KevEntry).filter_by(
        cve_id="CVE-2026-111497").count() == 1
    assert merged.sources == "cisa-kev,vulncheck-kev,eu-kev"
    # CISA owns the text; the others only fill what it left empty.
    assert merged.description == "CISA's description."
    assert merged.required_action == "Apply mitigations."
    assert merged.due_date == "2026-11-10"
    # …and the gaps the EU list fills are kept, not discarded.
    assert merged.euvd_id == "EUVD-2026-51097"
    assert merged.exploitation_type == "APT"
    assert merged.eu_evidence == "https://example.test/exploited"
    # Rows only one publisher listed still land.
    assert session.query(models.KevEntry).filter_by(
        cve_id="CVE-2026-999999").one().exploitation_type == "ransomware"
    assert session.query(models.KevEntry).filter_by(
        cve_id="CVE-2026-777777").one().sources == "vulncheck-kev"


def test_a_later_eu_row_does_not_overwrite_cisa(client):
    """Order of arrival must not decide which description the reader sees."""
    _, _, session = client
    kev_feeds.apply(session, kev_feeds._parse_eu(EU_PAYLOAD))
    kev_feeds.apply(session, kev_feeds._parse_cisa(CISA_PAYLOAD))
    session.commit()
    merged = session.get(models.KevEntry, "CVE-2026-111497")
    assert merged.description == "CISA's description."
    assert merged.sources == "cisa-kev,eu-kev"


# ── sync: one feed down is not a dead mirror ─────────────────────────────────

def test_a_failing_feed_is_reported_and_does_not_stop_the_others(client):
    _, _, session = client

    def boom():
        raise OSError("no route to enisa")

    result = kev_feeds.sync(session, fetchers={
        kev_feeds.CISA: lambda: kev_feeds._parse_cisa(CISA_PAYLOAD),
        kev_feeds.EU: boom,
        kev_feeds.VULNCHECK: lambda: kev_feeds._parse_vulncheck(VULNCHECK_PAYLOAD),
    })
    session.commit()
    by_slug = {item["source"]: item for item in result["sources"]}
    assert by_slug[kev_feeds.CISA]["ok"] is True
    assert by_slug[kev_feeds.EU]["ok"] is False
    assert "no route to enisa" in by_slug[kev_feeds.EU]["error"]
    # One CVE is in two catalogues: two rows on the screen, three writes.
    assert result["rows"] == 2
    assert result["written"] == 3
    assert session.get(models.KevEntry, "CVE-2026-111497") is not None
    # The per-source state is what the screen reads; a merged count cannot tell.
    state = session.get(models.KevFeedState, kev_feeds.EU)
    assert state.last_ok_at is None and "no route to enisa" in state.last_error


def test_without_a_token_vulncheck_is_a_state_not_an_error(client, monkeypatch):
    _, _, session = client
    result = kev_feeds.sync(session, fetchers={
        kev_feeds.CISA: lambda: kev_feeds._parse_cisa(CISA_PAYLOAD),
        kev_feeds.EU: lambda: kev_feeds._parse_eu(EU_PAYLOAD),
    })
    session.commit()
    by_slug = {item["source"]: item for item in result["sources"]}
    assert by_slug[kev_feeds.VULNCHECK]["ok"] is False
    assert by_slug[kev_feeds.VULNCHECK]["skipped"] == "missing credentials"
    assert by_slug[kev_feeds.CISA]["ok"] is True
    coverage = {item["source"]: item for item in kev_feeds.coverage(session)}
    assert coverage[kev_feeds.VULNCHECK]["status"] == "credentials missing"
    assert coverage[kev_feeds.CISA]["status"] == "connected"
    assert coverage[kev_feeds.EU]["status"] == "connected"


def test_kev_sources_can_narrow_the_set(client, monkeypatch):
    monkeypatch.setenv("KEV_SOURCES", "cisa-kev,eu-kev")
    assert [source.slug for source in kev_feeds.enabled_sources()] == [
        kev_feeds.CISA, kev_feeds.EU]
    monkeypatch.setenv("KEV_SOURCES", "nonsense")
    assert len(kev_feeds.enabled_sources()) == len(kev_feeds.SOURCES), (
        "a filter that matches nothing must not look like a dead mirror")


# ── the screen's contract ────────────────────────────────────────────────────

def test_the_catalog_reports_who_says_so_and_filters_by_publisher(client):
    http, headers, session = client
    kev_feeds.sync(session, fetchers={
        kev_feeds.CISA: lambda: kev_feeds._parse_cisa(CISA_PAYLOAD),
        kev_feeds.EU: lambda: kev_feeds._parse_eu(EU_PAYLOAD),
        kev_feeds.VULNCHECK: lambda: [],
    })
    session.commit()

    body = http.get("/api/v1/intel/kev", headers=headers).json()
    assert body["total"] == 2
    rows = {row["cve_id"]: row for row in body["data"]}
    assert rows["CVE-2026-111497"]["sources"] == ["cisa-kev", "eu-kev"]
    assert rows["CVE-2026-999999"]["sources"] == ["eu-kev"]
    assert rows["CVE-2026-111497"]["exploitation_type"] == "APT"

    only_eu = http.get("/api/v1/intel/kev?source=eu-kev", headers=headers).json()
    assert only_eu["total"] == 2
    only_cisa = http.get("/api/v1/intel/kev?source=cisa-kev", headers=headers).json()
    assert [row["cve_id"] for row in only_cisa["data"]] == ["CVE-2026-111497"]

    per_source = {item["source"]: item for item in body["coverage"]["sources"]}
    assert set(per_source) == {source.slug for source in kev_feeds.SOURCES}
    assert per_source["cisa-kev"]["status"] == "connected"
    # Three counts that answer three questions, and they are not the merged total.
    assert per_source["cisa-kev"]["advertised"] == 1, "what the catalogue published"
    assert per_source["cisa-kev"]["listed"] == 1, "rows in the mirror carrying the slug"
    assert per_source["cisa-kev"]["exclusive"] == 0, "the EU list carries this one too"
    assert per_source["eu-kev"]["listed"] == 2
    assert per_source["eu-kev"]["exclusive"] == 1
    assert per_source["vulncheck-kev"]["listed"] == 0


def test_one_entry_lists_every_publisher_for_the_cve(client):
    http, headers, session = client
    kev_feeds.sync(session, fetchers={
        kev_feeds.CISA: lambda: kev_feeds._parse_cisa(CISA_PAYLOAD),
        kev_feeds.EU: lambda: kev_feeds._parse_eu(EU_PAYLOAD),
        kev_feeds.VULNCHECK: lambda: [],
    })
    session.commit()
    body = http.get("/api/v1/intel/kev/CVE-2026-111497", headers=headers).json()
    assert body["known_exploited"] is True
    assert body["data"]["sources"] == ["cisa-kev", "eu-kev"]
    assert body["data"]["euvd_id"] == "EUVD-2026-51097"


def test_a_total_outage_is_a_502_that_names_every_source(client, monkeypatch):
    http, headers, _ = client

    def boom(timeout=0):
        raise OSError("offline")

    patched = tuple(kev_feeds.KevSource(source.slug, source.label, source.url, boom)
                    for source in kev_feeds.SOURCES)
    monkeypatch.setattr(kev_feeds, "SOURCES", patched)
    monkeypatch.setattr(kev_feeds, "BY_SLUG", {source.slug: source for source in patched})
    response = http.post("/api/v1/intel/sync", headers=headers)
    assert response.status_code == 502
    assert "cisa-kev" in response.json()["detail"]
    assert "offline" in response.json()["detail"]

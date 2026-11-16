"""The KEV catalog as a screen: what came out, and does it touch what we run.

Two defects this file exists to prevent, both found live:

* `fetch_kev` read `entry["title"]`, a field the CISA feed does not have — all 1769
  rows landed with a null name, so nothing could be searched or matched. The feed
  carries `vendorProject`, `product`, `vulnerabilityName` and `shortDescription`.
* a catalog nobody can filter is a lookup table. "¿existe alguna vuln nueva?" needs
  `since`, text, product and a join against the estate that does **not** require a
  matching finding to already exist.
"""
import json
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402
from backend.app.routers import intelligence  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/kev.db")
    monkeypatch.setenv("BOOTSTRAP_TOKEN", "boot")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "kev")

    # Three feed rows: the real Node2Shell advisory, one older, one due far away.
    session.add_all([
        models.KevEntry(cve_id="CVE-2026-111497", name="Google Brotli Unchecked "
                        "Return Value Vulnerability", title="Google Brotli",
                        vendor="Google", product="Brotli",
                        description="Google Brotli contains an unchecked return value "
                                    "vulnerability that can lead to remote code execution.",
                        required_action="Apply mitigations per vendor instructions.",
                        ransomware="Unknown", cwes="CWE-252, CWE-787",
                        date_added="2026-10-27", due_date="2026-11-10"),
        models.KevEntry(cve_id="CVE-2026-000001", name="Windows Old Thing",
                        vendor="Microsoft", product="Windows",
                        date_added="2026-01-05", due_date="2026-12-31",
                        ransomware="Known"),
        models.KevEntry(cve_id="CVE-2026-000002", name="Chrome Widget",
                        vendor="Google", product="Chrome",
                        date_added="2026-11-01", due_date="2026-11-20"),
    ])
    # The estate: a build holding Node, and a finding that already ties it to the CVE.
    component = models.Component(org_id=org.id,
                                 identity_key="pkg:docker/node@22-alpine",
                                 purl="pkg:docker/node@22-alpine", name="node")
    session.add(component)
    session.flush()
    session.add(models.Vulnerability(id="vuln-1", source_id="CVE-2026-111497",
                                     source="nvd", cve_id="CVE-2026-111497",
                                     title="brotli", severity="CRITICAL"))
    session.flush()
    session.add(models.Finding(org_id=org.id, kind="vulnerability",
                               fingerprint="fp-1", source="nvd",
                               title="CVE-2026-111497 on node",
                               severity="CRITICAL", status="open",
                               component_id=component.id, vulnerability_id="vuln-1"))
    project = models.Project(org_id=org.id, name="AUREA", slug="aurea")
    session.add(project)
    session.flush()
    session.add(models.EpssScore(cve_id="CVE-2026-111497", epss="0.826410",
                                 percentile="0.996690"))
    session.commit()

    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}, session


def test_fetch_kev_reads_the_fields_the_feed_actually_has(monkeypatch):
    payload = {"vulnerabilities": [{
        "cveID": "CVE-2026-111497", "vendorProject": "Google", "product": "Brotli",
        "vulnerabilityName": "Google Brotli Unchecked Return Value Vulnerability",
        "shortDescription": "…can lead to remote code execution.",
        "requiredAction": "Apply mitigations.", "dueDate": "2026-11-10",
        "dateAdded": "2026-10-27", "knownRansomwareCampaignUse": "Unknown",
        "cwes": ["CWE-252", "CWE-787"]}]}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps(payload).encode()

    monkeypatch.setattr(intelligence.urllib.request, "urlopen",
                        lambda *args, **kwargs: FakeResponse())
    row = intelligence.fetch_kev()[0]
    assert row["name"] == "Google Brotli Unchecked Return Value Vulnerability"
    assert row["vendor"] == "Google" and row["product"] == "Brotli"
    assert row["cwes"] == "CWE-252, CWE-787"
    assert row["required_action"] == "Apply mitigations."


def test_the_catalog_is_newest_first_and_reports_its_own_freshness(client):
    http, headers, _ = client
    body = http.get("/api/v1/intel/kev", headers=headers).json()
    assert body["total"] == 3
    assert [row["cve_id"] for row in body["data"]][0] == "CVE-2026-000002"
    assert body["coverage"]["feed"] == "connected"
    assert body["coverage"]["rows"] == 3


def test_since_answers_did_anything_new_come_out(client):
    http, headers, _ = client
    body = http.get("/api/v1/intel/kev?since=2026-10-01", headers=headers).json()
    assert body["total"] == 2
    assert body["counts"]["new_since"] == 2
    assert all(row["date_added"] >= "2026-10-01" for row in body["data"])


def test_text_and_product_filters_without_a_finding(client):
    """The catalog is readable even when nothing in the estate is affected."""
    http, headers, _ = client
    body = http.get("/api/v1/intel/kev?q=unchecked",
                    headers=headers).json()
    assert body["total"] == 1
    assert body["data"][0]["cve_id"] == "CVE-2026-111497"
    assert body["data"][0]["epss"] == "0.826410"
    assert body["data"][0]["days_to_due"] is not None

    chrome = http.get("/api/v1/intel/kev?product=chrome", headers=headers).json()
    assert [row["cve_id"] for row in chrome["data"]] == ["CVE-2026-000002"]


def test_matched_uses_the_exact_cve_join_not_just_the_product_word(client):
    """KEV calls it "Google Brotli"; the estate holds `node`. The finding is the join."""
    http, headers, _ = client
    body = http.get("/api/v1/intel/kev?matched=true", headers=headers).json()
    assert body["total"] == 1
    row = body["data"][0]
    assert row["cve_id"] == "CVE-2026-111497"
    assert row["matches"][0]["kind"] == "finding"
    assert "node" in row["matches"][0]["label"]

    # Without a finding, product words still find a component by name.
    only_words = http.get("/api/v1/intel/kev?matched=true&product=brotli",
                          headers=headers).json()
    assert only_words["total"] == 1, "the exact join is the one that catches this"


def test_a_bad_date_is_a_422_not_a_silent_empty_list(client):
    http, headers, _ = client
    response = http.get("/api/v1/intel/kev?since=last-monday", headers=headers)
    assert response.status_code == 422
    assert "ISO date" in response.json()["detail"]


# ── the lore: a nickname is not a row ────────────────────────────────────────

def test_a_nickname_resolves_to_the_cve_and_to_what_the_estate_holds(client):
    """`node2shell` is in no table; the CVE it names has two open findings here."""
    http, headers, _ = client
    body = http.get("/api/v1/intel/advisory?q=node2shell", headers=headers).json()["data"]
    assert body["resolved"] is True
    assert body["how"] == "alias"
    assert body["cve_id"] == "CVE-2026-111497"
    assert body["kev"]["product"] == "Brotli"
    assert body["estate"]["open"] == 1
    assert any("node" in label for label in body["estate"]["components"])


def test_the_same_advisory_reached_by_text_is_marked_as_a_guess(client):
    http, headers, _ = client
    body = http.get("/api/v1/intel/advisory?q=unchecked", headers=headers).json()["data"]
    assert body["resolved"] is True
    assert body["how"] == "text"
    assert body["cve_id"] == "CVE-2026-111497"


def test_an_unresolved_name_says_unknown_instead_of_clean(client):
    http, headers, _ = client
    body = http.get("/api/v1/intel/advisory?q=notavuln",
                    headers=headers).json()["data"]
    assert body["resolved"] is False
    assert body["estate"]["findings"] == 0
    assert "unknown, not 'not affected'" in body["why"]


def test_the_alias_table_normalises_what_people_type():
    from backend.app import advisory_names

    for typed in ("node2shell", "Node 2 Shell", "Node-2-Shell", "  NODE2SHELL "):
        assert advisory_names.resolve(typed) == "CVE-2026-111497", typed
    assert advisory_names.resolve("CVE-2021-44228") == "CVE-2021-44228"
    assert advisory_names.resolve("nada-que-ver") is None


def test_the_ai_tools_include_the_lore_and_the_catalog(client):
    """The specialist must be able to ask 'what is this name' and 'what is new'."""
    from backend.app.ai import dispatch, specialists, tools

    for name in ("advisory_resolve", "intel_kev_catalog"):
        assert name in tools.BY_NAME, name
        assert name in dispatch.dispatched(), name
    assert "advisory_resolve" in specialists.tools_for("estate.inventory")
    assert "intel_kev_catalog" in specialists.tools_for("estate.inventory")
    assert "advisory_resolve" in specialists.tools_for("intel.cve")

    _, headers, session = client
    org = session.query(models.Organization).one()
    resolved = dispatch.call("advisory_resolve", {"q": "node2shell"},
                             org=org, session=session)["data"]
    assert resolved["resolved"] is True and resolved["estate"]["open"] == 1

    # No arguments at all: the Query defaults must arrive as values, not objects.
    catalog = dispatch.call("intel_kev_catalog", {}, org=org, session=session)
    assert catalog["total"] == 3

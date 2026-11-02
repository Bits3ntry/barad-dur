"""v0 vulnerabilities: aggregation over visible findings, not the catalog.

The spec's sharpest sentence here is that a global advisory catalog is not a
list of CVEs affecting the inventory. These tests hold that line: a CVE with no
finding never appears, a manual IDOR never appears, and enrichment says
"unknown" instead of inventing a number.
"""
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


@pytest.fixture()
def seeded(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/vulns.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="bitsentry", name="Bitsentry")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()

    project = models.Project(org_id=org.id, name="AUREA", slug="aurea")
    project_b = models.Project(org_id=org.id, name="AUREA web", slug="aurea-web")
    foreign_project = models.Project(org_id=other.id, name="Other", slug="other")
    session.add_all([project, project_b, foreign_project])
    session.flush()

    version = models.ProjectVersion(project_id=project.id, version="v3")
    session.add(version)
    session.flush()

    component = models.Component(org_id=org.id, identity_key="pkg:pypi/django@3.2.0",
                                 purl="pkg:pypi/django@3.2.0", name="django",
                                 version="3.2.0")
    session.add(component)
    session.flush()

    advisory = models.Vulnerability(source_id="GHSA-aaaa", source="osv",
                                    cve_id="CVE-2026-0001", title="Django issue",
                                    severity="high")
    untouched = models.Vulnerability(source_id="GHSA-bbbb", source="osv",
                                     cve_id="CVE-2026-9999", title="not used here")
    session.add_all([advisory, untouched])
    session.flush()

    asset = models.Asset(org_id=org.id, type="domain", value="api-aurea.bitsentry.xyz",
                         source="scope", project_id=project.id)
    linked_asset = models.Asset(org_id=org.id, type="ip", value="203.0.113.9",
                                source="manual")
    session.add_all([asset, linked_asset])
    session.flush()
    session.add(models.AssetLink(org_id=org.id, asset_id=linked_asset.id,
                                 entity_type="project", entity_id=project_b.id,
                                 relation="serves"))
    session.add_all([
        models.KevEntry(cve_id="CVE-2026-0001", date_added="2026-01-02",
                        due_date="2026-02-02", source="cisa.gov"),
        models.EpssScore(cve_id="CVE-2026-0001", epss="0.42", percentile="0.97"),
    ])

    findings = [
        models.Finding(org_id=org.id, project_id=project.id, kind="vulnerability",
                       fingerprint="fp-1", source="osv", title="Django 3.2 issue",
                       severity="HIGH", vulnerability_id=advisory.id,
                       component_id=component.id, last_seen_version_id=version.id,
                       priority="P1", status="open"),
        models.Finding(org_id=org.id, project_id=project_b.id, kind="vulnerability",
                       fingerprint="fp-2", source="osv", title="Django 3.2 issue",
                       severity="CRITICAL", vulnerability_id=advisory.id,
                       priority="P0", status="acknowledged"),
        models.Finding(org_id=org.id, project_id=project.id, kind="code-weakness",
                       fingerprint="fp-manual", source="manual",
                       title="IDOR on invoices", severity="HIGH", status="open"),
        models.Finding(org_id=org.id, project_id=project.id, kind="vulnerability",
                       fingerprint="fp-3", source="osv", title="suppressed row",
                       severity="LOW", vulnerability_id=advisory.id,
                       priority="P3", status="suppressed"),
    ]
    session.add_all(findings)
    session.flush()
    org_key = create_key(session, org.id, "vulns")
    other_key = create_key(session, other.id, "vulns-other")
    session.commit()

    from fastapi.testclient import TestClient
    return (TestClient(app), {"X-API-Key": org_key}, {"X-API-Key": other_key},
            session_factory, advisory.id, findings[0].id, findings[1].id, findings[3].id)


def test_aggregates_only_cves_with_visible_findings(seeded):
    test_client, headers, _other, _sf, _adv, _f1, _f2, _suppressed = seeded
    body = test_client.get("/api/v1/vulnerabilities", headers=headers).json()
    assert body["total"] == 1
    row = body["data"][0]
    assert row["cve_id"] == "CVE-2026-0001"
    assert row["findings"] == 2, "the suppressed finding is out of the default view"
    assert row["open_findings"] == 2
    assert row["severity"] == "CRITICAL", "aggregate severity is the worst finding"
    assert row["priority"] == "P0"
    assert {p["slug"] for p in row["projects"]} == {"aurea", "aurea-web"}
    assert row["assets"]["count"] == 2, "one direct + one through a typed link"
    assert row["enrichment"]["kev"]["listed"] is True
    assert row["enrichment"]["kev"]["source"] == "cisa.gov"
    assert row["enrichment"]["kev"]["fetched_at"]
    assert row["enrichment"]["epss"]["score"] == "0.42"
    assert row["enrichment"]["exploit"] == {"known": False, "available": None,
                                            "reason": "no exploit feed connected"}
    assert row["versions_known"] is False
    assert row["affected_versions"] == [] and row["fixed_versions"] == []
    assert "unknown, not empty" in row["versions_reason"]

    ids = {item["cve_id"] for item in body["data"]}
    assert "CVE-2026-9999" not in ids, "the catalog is not the inventory"


def test_manual_findings_and_suppressed_only_cves_stay_out(seeded):
    test_client, headers, _other, _sf, _adv, _f1, _f2, _suppressed = seeded
    listing = test_client.get("/api/v1/vulnerabilities?include_suppressed=true",
                              headers=headers).json()
    assert listing["data"][0]["findings"] == 3

    findings = test_client.get("/api/v1/findings?q=IDOR", headers=headers).json()
    assert findings["total"] == 1
    assert findings["data"][0]["cve_id"] is None


def test_detail_lists_the_concrete_findings(seeded):
    test_client, headers, _other, _sf, _adv, _f1, _f2, _suppressed = seeded
    detail = test_client.get("/api/v1/vulnerabilities/CVE-2026-0001",
                             headers=headers).json()["data"]
    assert detail["cve_id"] == "CVE-2026-0001"
    rows = detail["findings_detail"]
    assert {row["id"] for row in rows} == {_f1, _f2}
    assert rows[0]["severity"] == "CRITICAL", "worst first"
    by_id = {row["id"]: row for row in rows}
    assert by_id[_f1]["component"] == "pkg:pypi/django@3.2.0"
    assert by_id[_f1]["version"] == "v3"
    assert by_id[_f2]["component"] is None
    assert "CVE-2026-9999" not in test_client.get(
        "/api/v1/vulnerabilities/CVE-2026-9999", headers=headers).text


def test_bulk_preview_then_apply_is_bounded_and_audited(seeded):
    test_client, headers, other_headers, sf, _adv, f1, f2, suppressed = seeded
    preview = test_client.post("/api/v1/vulnerabilities/CVE-2026-0001/bulk-preview",
                               json={"finding_ids": [f1, f2, suppressed],
                                     "status": "resolved"}, headers=headers).json()["data"]
    assert preview["would_change"] == 2
    assert preview["skipped"][0]["finding_id"] == suppressed
    assert "suppressed" in preview["skipped"][0]["reason"]

    # Preview writes nothing.
    session = sf()()
    assert session.get(models.Finding, f1).status == "open"
    session.close()

    foreign = test_client.post("/api/v1/vulnerabilities/CVE-2026-0001/bulk-preview",
                               json={"finding_ids": [f1], "status": "resolved"},
                               headers=other_headers).json()["data"]
    assert foreign["would_change"] == 0
    assert foreign["skipped"][0]["reason"] == "not found in this organization"

    applied = test_client.post("/api/v1/vulnerabilities/CVE-2026-0001/bulk-status",
                               params={"actor": "tester"},
                               json={"finding_ids": [f1, f2, suppressed],
                                     "status": "resolved"}, headers=headers).json()["data"]
    assert applied["changed"] == 2
    assert applied["skipped"] == [suppressed]

    session = sf()()
    assert session.get(models.Finding, f1).status == "resolved"
    assert session.get(models.Finding, suppressed).status == "suppressed"
    session.close()

    actions = {row["action"] for row in test_client.get(
        "/api/v1/activity?resource_type=finding", headers=headers).json()["data"]}
    assert "finding.status_changed" in actions

    listing = test_client.get("/api/v1/vulnerabilities", headers=headers).json()
    assert listing["total"] == 1
    assert listing["data"][0]["open_findings"] == 0


def test_vulnerabilities_are_isolated(seeded):
    test_client, _headers, other_headers, _sf, _adv, _f1, _f2, _suppressed = seeded
    assert test_client.get("/api/v1/vulnerabilities",
                           headers=other_headers).json()["total"] == 0
    assert test_client.get("/api/v1/vulnerabilities/CVE-2026-0001",
                           headers=other_headers).status_code == 404
    assert test_client.get("/api/v1/vulnerabilities/meta/summary",
                           headers=other_headers).json()["data"] == {
        "cves": 0, "kev": 0, "findings": 0, "unknown_enrichment": 0}

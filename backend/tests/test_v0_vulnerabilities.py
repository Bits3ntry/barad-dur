"""Vulnerabilities: one row per PROBLEM, grouped from findings, never the catalog.

Two readings of the same data, and the difference matters:

* findings are occurrences (the same SQL injection in two endpoints is two),
* vulnerabilities are the problem (one row, two places, one fix).

The spec's other sharp line is that a global advisory catalog is not a list of
CVEs affecting the inventory: a CVE with no finding never appears here. These
tests hold both lines, plus the honesty rule — enrichment says "unknown" with a
reason instead of inventing a number.
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
                       vector="dependency-cve",
                       fingerprint="fp-1", source="osv", title="Django 3.2 issue",
                       severity="HIGH", vulnerability_id=advisory.id, rule_id="CVE-2026-0001",
                       component_id=component.id, last_seen_version_id=version.id,
                       priority="P1", status="open",
                       detail='{"cvss_score": 7.5, "fixed_version": "3.2.24"}'),
        models.Finding(org_id=org.id, project_id=project_b.id, kind="vulnerability",
                       vector="dependency-cve",
                       fingerprint="fp-2", source="osv", title="Django 3.2 issue",
                       severity="CRITICAL", vulnerability_id=advisory.id, rule_id="CVE-2026-0001",
                       component_id=component.id,
                       priority="P0", status="acknowledged"),
        models.Finding(org_id=org.id, project_id=project.id, kind="code-weakness",
                       vector="sast",
                       fingerprint="fp-manual", source="manual", rule_id="manual.idor",
                       title="IDOR on invoices", severity="HIGH", status="open"),
        models.Finding(org_id=org.id, project_id=project.id, kind="code-weakness",
                       vector="sast",
                       fingerprint="fp-manual-2", source="scan", rule_id="manual.idor",
                       title="IDOR on invoices", severity="HIGH", status="open",
                       path="app/invoices.py", line=42),
        models.Finding(org_id=org.id, project_id=project.id, kind="vulnerability",
                       vector="credential",
                       fingerprint="fp-secret", source="scan", rule_id="generic-api-key",
                       title="Exposed credential", severity="CRITICAL", status="open",
                       path="config/settings.py", line=17),
        models.Finding(org_id=org.id, project_id=project.id, kind="vulnerability",
                       vector="credential",
                       fingerprint="fp-secret-2", source="scan", rule_id="generic-api-key",
                       title="Exposed credential", severity="CRITICAL", status="open",
                       path="scripts/deploy.sh", line=9),
        models.Finding(org_id=org.id, project_id=project.id, kind="vulnerability",
                       fingerprint="fp-3", source="osv", title="suppressed row",
                       severity="LOW", vulnerability_id=advisory.id,
                       component_id=component.id,
                       priority="P3", status="suppressed"),
    ]
    session.add_all(findings)
    session.flush()
    org_key = create_key(session, org.id, "vulns")
    other_key = create_key(session, other.id, "vulns-other")
    session.commit()

    from fastapi.testclient import TestClient
    return (TestClient(app), {"X-API-Key": org_key}, {"X-API-Key": other_key},
            session_factory, advisory.id, findings[0].id, findings[1].id, findings[6].id)


def _by_signature(body, signature):
    return next(row for row in body["data"] if row["signature"] == signature)


def test_a_cve_aggregates_its_findings_and_nothing_from_the_catalog(seeded):
    test_client, headers, _other, _sf, _adv, _f1, _f2, _suppressed = seeded
    body = test_client.get("/api/v1/vulnerabilities", headers=headers).json()

    row = _by_signature(body, "CVE-2026-0001")
    assert row["vector"] == "dependency-cve"
    assert row["findings"] == 2, "the suppressed finding is out of the default view"
    assert row["open_findings"] == 2
    assert row["severity"] == "CRITICAL", "aggregate severity is the worst finding"
    assert row["priority"] == "P0"
    assert {p["slug"] for p in row["projects"]} == {"aurea", "aurea-web"}
    assert row["assets"]["count"] == 2, "one direct + one through a typed link"
    assert row["components"][0]["name"] == "django"

    assert row["enrichment"]["kev"]["listed"] is True
    assert row["enrichment"]["kev"]["source"] == "cisa.gov"
    assert row["enrichment"]["kev"]["fetched_at"]
    assert row["enrichment"]["epss"]["score"] == "0.42"
    assert row["enrichment"]["exploit"]["available"] is True
    assert row["cvss"]["score"] == 7.5
    assert row["fix"]["available"] is True and row["fix"]["versions"] == ["3.2.24"]

    ids = {item["cve_id"] for item in body["data"]}
    assert "CVE-2026-9999" not in ids, "the catalog is not the inventory"
    assert body["counters"]["vulnerabilities"] == len(body["data"])
    assert body["counters"]["findings"] >= sum(r["findings"] for r in body["data"])


def test_the_same_problem_in_two_places_is_one_row(seeded):
    """The rule the console depends on: 1 problem, N findings."""
    test_client, headers, _other, _sf, _adv, _f1, _f2, _suppressed = seeded
    body = test_client.get("/api/v1/vulnerabilities", headers=headers).json()

    idor = _by_signature(body, "manual.idor")
    assert idor["vector"] == "sast"
    assert idor["cve_id"] is None
    assert idor["findings"] == 2, "two occurrences, one problem"
    assert {loc["path"] for loc in idor["locations"]} == {None, "app/invoices.py"}

    secret = _by_signature(body, "generic-api-key")
    assert secret["vector"] == "credential"
    assert secret["findings"] == 2
    assert secret["remediation"] == "Rotate the credential"
    assert {loc["path"] for loc in secret["locations"]} == {"config/settings.py",
                                                           "scripts/deploy.sh"}


def test_suppressed_findings_are_out_of_the_default_view(seeded):
    test_client, headers, _other, _sf, _adv, _f1, _f2, _suppressed = seeded
    default = test_client.get("/api/v1/vulnerabilities", headers=headers).json()
    assert _by_signature(default, "CVE-2026-0001")["findings"] == 2

    expanded = test_client.get("/api/v1/vulnerabilities?include_suppressed=true",
                               headers=headers).json()
    assert _by_signature(expanded, "CVE-2026-0001")["findings"] == 3


def test_detail_lists_the_concrete_findings(seeded):
    test_client, headers, _other, _sf, _adv, _f1, _f2, _suppressed = seeded
    detail = test_client.get("/api/v1/vulnerabilities/CVE-2026-0001",
                             headers=headers).json()["data"]
    assert detail["cve_id"] == "CVE-2026-0001"
    rows = detail["locations"]
    assert {row["finding_id"] for row in rows} == {_f1, _f2}
    assert rows[0]["severity"] == "CRITICAL", "worst first"
    by_id = {row["finding_id"]: row for row in rows}
    assert by_id[_f1]["component"] == "django"
    assert by_id[_f1]["component_version"] == "3.2.0"
    assert by_id[_f2]["component"] == "django", "same package, different project"
    assert test_client.get("/api/v1/vulnerabilities/CVE-2026-9999",
                           headers=headers).status_code == 404


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


def test_one_status_change_moves_every_finding_of_the_problem(seeded):
    """A vulnerability has one lifecycle even with two occurrences."""
    test_client, headers, _other, sf, _adv, _f1, _f2, _suppressed = seeded
    result = test_client.patch("/api/v1/vulnerabilities/manual.idor/status",
                               json={"status": "acknowledged",
                                     "reason": "triaged in the console"},
                               headers=headers).json()["data"]
    assert result["findings"] == 2
    session = sf()()
    owners = (session.query(models.Finding)
              .filter_by(rule_id="manual.idor").all())
    assert {row.status for row in owners} == {"acknowledged"}
    assert {row.status_reason for row in owners} == {"triaged in the console"}
    session.close()


def test_vulnerabilities_are_isolated(seeded):
    test_client, _headers, other_headers, _sf, _adv, _f1, _f2, _suppressed = seeded
    assert test_client.get("/api/v1/vulnerabilities",
                           headers=other_headers).json()["total"] == 0
    assert test_client.get("/api/v1/vulnerabilities/CVE-2026-0001",
                           headers=other_headers).status_code == 404
    summary = test_client.get("/api/v1/vulnerabilities/meta/summary",
                              headers=other_headers).json()["data"]
    assert summary["vulnerabilities"] == 0
    assert summary["findings"] == 0

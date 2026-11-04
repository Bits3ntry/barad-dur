"""An SBOM is also an advisory list: ingest it as one.

The first live pipeline produced 123 components and 67 CVEs, and the platform
recorded only the components — the console then showed an empty Vulnerabilities
screen for a repository that had 67 known issues. These tests hold the fix:
components still land as inventory, and the advisories the artifact carried
become deduped findings with their CVSS, fixed version and advisory link.
"""
import json
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import ingest, models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


def _document(*, extra_component: bool = False, unknown_ref: bool = False) -> dict:
    components = [
        {"type": "library", "name": "starlette", "version": "0.46.2",
         "purl": "pkg:pypi/starlette@0.46.2", "bom-ref": "pkg:pypi/starlette@0.46.2"},
        {"type": "library", "name": "pyjwt", "version": "2.10.1",
         "purl": "pkg:pypi/pyjwt@2.10.1", "bom-ref": "pkg:pypi/pyjwt@2.10.1"},
    ]
    if extra_component:
        components.append({"type": "library", "name": "mcp", "version": "1.12.4",
                           "purl": "pkg:pypi/mcp@1.12.4",
                           "bom-ref": "pkg:pypi/mcp@1.12.4"})
    vulnerabilities = [
        {"id": "CVE-2025-62727",
         "source": {"name": "trivy", "url": "https://avd.aquasec.com/example"},
         "ratings": [{"score": 7.5, "severity": "high", "method": "CVSSv3",
                      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
         "description": "Starlette denial of service via multipart boundary.",
         "recommendation": "Upgrade starlette to 0.47.2",
         "advisories": [{"url": "https://github.com/advisories/x"}],
         "affects": [{"ref": "pkg:pypi/starlette@0.46.2"}]},
        {"id": "CVE-2026-101917",
         "ratings": [{"score": 9.8, "severity": "critical", "method": "CVSSv3",
                      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
         "description": "PyJWT accepts a forged token.",
         "recommendation": "Upgrade pyjwt to 2.11.0",
         "affects": [{"ref": "pkg:pypi/pyjwt@2.10.1"}]},
    ]
    if unknown_ref:
        vulnerabilities.append({
            "id": "CVE-2030-0001",
            "ratings": [{"score": 5.0, "severity": "medium"}],
            "description": "Affects a package this document does not contain.",
            "recommendation": "Upgrade whatever to 9.9.9",
            "affects": [{"ref": "pkg:pypi/absent@1.0.0"}]})
    return {"bomFormat": "CycloneDX", "specVersion": "1.6",
            "metadata": {"component": {"type": "application", "name": "aurea",
                                       "version": "21.7.8", "bom-ref": "app"}},
            "components": components,
            "vulnerabilities": vulnerabilities}


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/sbomv.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="bitsentry", name="Bitsentry")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "sbomv")
    session.commit()
    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}, org.id, session_factory


def test_the_artifact_advisories_become_findings(env):
    _client, _headers, org_id, sf = env
    session = sf()()
    raw = json.dumps(_document()).encode()
    result = ingest.ingest_document(session, org_id, raw, source="test",
                                    project_override="aurea", version_override="21.7.8")
    session.commit()

    receipt = session.get(models.SbomImport, result["import_id"])
    assert receipt.vulnerabilities_received == 2
    assert receipt.vulnerabilities_created == 2
    assert receipt.vulnerabilities_unresolved == 0

    findings = (session.query(models.Finding)
                .filter_by(org_id=org_id, vector="dependency-cve").all())
    assert len(findings) == 2
    by_cve = {finding.rule_id: finding for finding in findings}

    starlette = by_cve["CVE-2025-62727"]
    assert starlette.kind == "vulnerability"
    assert starlette.severity == "HIGH"
    assert starlette.component_id is not None
    assert starlette.vulnerability_id is not None
    assert starlette.recommendation == "Upgrade to 0.47.2"
    evidence = json.loads(starlette.detail)
    assert evidence["cvss_score"] == 7.5
    assert evidence["fixed_version"] == "0.47.2"
    assert evidence["cvss_vector"].startswith("CVSS:3.1/")
    assert evidence["advisory_url"] == "https://github.com/advisories/x"

    advisory = session.get(models.Vulnerability, starlette.vulnerability_id)
    assert advisory.cve_id == "CVE-2025-62727"
    assert advisory.source == "sbom"

    critical = by_cve["CVE-2026-101917"]
    assert critical.severity == "CRITICAL"
    session.close()


def test_reingesting_the_same_advisories_refreshes_instead_of_duplicating(env):
    _client, _headers, org_id, sf = env
    session = sf()()
    ingest.ingest_document(session, org_id, json.dumps(_document()).encode(),
                           source="test", project_override="aurea",
                           version_override="21.7.8")
    session.commit()
    # A second document differs in bytes (an extra component) but states the
    # same advisories for the same packages.
    second = ingest.ingest_document(
        session, org_id, json.dumps(_document(extra_component=True)).encode(),
        source="test", project_override="aurea", version_override="21.7.8")
    session.commit()

    receipt = session.get(models.SbomImport, second["import_id"])
    assert receipt.vulnerabilities_created == 0
    assert receipt.vulnerabilities_refreshed == 2
    assert (session.query(models.Finding)
            .filter_by(org_id=org_id, vector="dependency-cve").count()) == 2
    session.close()


def test_an_advisory_about_an_absent_package_is_counted_not_guessed(env):
    _client, _headers, org_id, sf = env
    session = sf()()
    result = ingest.ingest_document(
        session, org_id, json.dumps(_document(unknown_ref=True)).encode(),
        source="test", project_override="aurea", version_override="21.7.8")
    session.commit()
    receipt = session.get(models.SbomImport, result["import_id"])
    assert receipt.vulnerabilities_unresolved == 1
    assert (session.query(models.Finding)
            .filter_by(org_id=org_id, rule_id="CVE-2030-0001").count()) == 0
    session.close()


def test_the_console_lists_one_row_per_problem_with_its_fix(env):
    client, headers, org_id, sf = env
    session = sf()()
    ingest.ingest_document(session, org_id, json.dumps(_document()).encode(),
                           source="test", project_override="aurea",
                           version_override="21.7.8")
    session.commit()
    session.close()

    body = client.get("/api/v1/vulnerabilities", headers=headers).json()
    assert body["total"] == 2
    assert body["counters"]["findings"] == 2
    by_cve = {row["cve_id"]: row for row in body["data"]}

    row = by_cve["CVE-2025-62727"]
    assert row["vector"] == "dependency-cve"
    assert row["fix"]["available"] is True
    assert row["fix"]["versions"] == ["0.47.2"]
    assert row["cvss"]["score"] == 7.5
    assert row["remediation"] == "Upgrade the package"
    assert row["components"][0]["name"] == "starlette"
    assert row["severity"] == "HIGH"

    # Reachability is stated, not guessed: no asset is attached to the project.
    assert row["reachable"] is False
    assert "no asset" in row["assets"]["coverage"]

    detail = client.get("/api/v1/vulnerabilities/CVE-2025-62727", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["data"]["locations"][0]["component"] == "starlette"

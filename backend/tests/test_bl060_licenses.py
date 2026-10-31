"""BL-060 acceptance: license inventory, policies, verdicts, exceptions."""
import datetime
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

SBOM = {
    "bomFormat": "CycloneDX", "specVersion": "1.5",
    "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
    "metadata": {"component": {"type": "application", "name": "lic-app"}},
    "components": [
        {"type": "library", "name": "requests", "version": "2.32.3",
         "purl": "pkg:pypi/requests@2.32.3",
         "licenses": [{"license": {"id": "Apache-2.0"}}]},
        {"type": "library", "name": "gpl-lib", "version": "1.0.0",
         "purl": "pkg:pypi/gpl-lib@1.0.0",
         "licenses": [{"license": {"id": "GPL-3.0-only"}}]},
        {"type": "library", "name": "multi", "version": "0.1",
         "purl": "pkg:pypi/multi@0.1",
         "licenses": [{"license": {"id": "MIT"}}, {"license": {"id": "BSD-3-Clause"}}]},
    ],
    "dependencies": [],
}


@pytest.fixture()
def lic_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/lic.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    key = create_key(session, org.id, "lic")
    other_key = create_key(session, other.id, "lic2")
    project = models.Project(org_id=org.id, slug="lic-app", name="lic-app")
    session.add(project)
    session.flush()
    session.add(models.ProjectVersion(project_id=project.id, version="1.0"))
    session.commit()
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key},
            {"X-API-Key": other_key}, session)


def _ingest(test_client, headers, payload=None):
    body = json.dumps(payload or SBOM).encode()
    return test_client.post("/api/v1/sbom?project=lic-app&version=1.0",
                            content=body,
                            headers={**headers,
                                     "Content-Type": "application/octet-stream"})


def test_inventory_from_sbom_and_idempotency(lic_client):
    test_client, headers, _other, session = lic_client
    assert _ingest(test_client, headers).status_code in (200, 201)
    inventory = test_client.get(
        "/api/v1/license-inventory?project=lic-app&version=1.0",
        headers=headers).json()
    licenses = sorted({row["license"] for row in inventory["data"]})
    assert licenses == ["Apache-2.0", "BSD-3-Clause", "GPL-3.0-only", "MIT"]
    assert inventory["total"] == 4

    # Re-ingest same SBOM: no duplicate license rows.
    assert _ingest(test_client, headers).status_code in (200, 201)
    again = test_client.get(
        "/api/v1/license-inventory?project=lic-app&version=1.0",
        headers=headers).json()
    assert again["total"] == 4


def test_policy_evaluation_deny_allow_and_unknown(lic_client):
    test_client, headers, _other, session = lic_client
    _ingest(test_client, headers)
    policy = test_client.post("/api/v1/license-policies", json={
        "name": "stdlib", "allow_list": "Apache-2.0, MIT, BSD-3-Clause",
        "deny_list": "GPL-3.0-only", "unknown_action": "warn",
        "actor": "gate"}, headers=headers)
    assert policy.status_code == 200, policy.text

    result = test_client.post("/api/v1/license-policies/evaluate", json={
        "project": "lic-app", "version": "1.0"}, headers=headers).json()["data"]
    assert result["policy"]["name"] == "stdlib"
    verdicts = {(row["component"], row["license"]): row["verdict"]
                for row in result["results"]}
    assert verdicts[("requests", "Apache-2.0")] == "allowed"
    assert verdicts[("gpl-lib", "GPL-3.0-only")] == "denied"
    assert verdicts[("multi", "MIT")] == "allowed"
    assert result["counts"]["denied"] == 1


def test_exception_waives_until_expiry(lic_client):
    test_client, headers, _other, session = lic_client
    _ingest(test_client, headers)
    test_client.post("/api/v1/license-policies", json={
        "name": "strict", "deny_list": "GPL-3.0-only", "actor": "gate"},
        headers=headers)
    # Find the identity key of gpl-lib.
    inventory = test_client.get(
        "/api/v1/license-inventory?project=lic-app&version=1.0",
        headers=headers).json()["data"]
    identity = next(row["identity_key"] for row in inventory
                    if row["component"] == "gpl-lib")

    created = test_client.post("/api/v1/license-exceptions", json={
        "component_identity": identity, "license_id": "GPL-3.0-only",
        "reason": "internal tool, legal signed off", "approved_by": "legal",
        "expires_in_days": 30}, headers=headers)
    assert created.status_code == 200, created.text

    result = test_client.post("/api/v1/license-policies/evaluate", json={
        "project": "lic-app", "version": "1.0"}, headers=headers).json()["data"]
    gpl = next(row for row in result["results"] if row["license"] == "GPL-3.0-only")
    assert gpl["verdict"] == "excepted"
    assert result["counts"]["excepted"] == 1

    # Expire it directly: verdict returns to denied.
    row = session.query(models.LicenseException).one()
    row.expires_at = models.utcnow() - datetime.timedelta(days=1)
    session.commit()
    expired = test_client.post("/api/v1/license-policies/evaluate", json={
        "project": "lic-app", "version": "1.0"}, headers=headers).json()["data"]
    gpl_now = next(row for row in expired["results"] if row["license"] == "GPL-3.0-only")
    assert gpl_now["verdict"] == "denied"


def test_project_policy_overrides_org_policy(lic_client):
    test_client, headers, _other, session = lic_client
    _ingest(test_client, headers)
    project = session.query(models.Project).one()
    test_client.post("/api/v1/license-policies", json={
        "name": "org-wide", "deny_list": "GPL-3.0-only", "actor": "gate"},
        headers=headers)
    test_client.post("/api/v1/license-policies", json={
        "name": "project-lenient", "scope_type": "project",
        "scope_id": project.id, "deny_list": "", "actor": "gate"},
        headers=headers)
    result = test_client.post("/api/v1/license-policies/evaluate", json={
        "project": "lic-app", "version": "1.0"}, headers=headers).json()["data"]
    assert result["policy"]["name"] == "project-lenient"
    gpl = next(row for row in result["results"] if row["license"] == "GPL-3.0-only")
    assert gpl["verdict"] != "denied"


def test_tenant_isolation(lic_client):
    test_client, headers, other_headers, _session = lic_client
    _ingest(test_client, headers)
    test_client.post("/api/v1/license-policies", json={
        "name": "p", "deny_list": "GPL-3.0-only", "actor": "gate"}, headers=headers)
    assert test_client.get("/api/v1/license-policies",
                           headers=other_headers).json()["total"] == 0
    assert test_client.get("/api/v1/license-exceptions",
                           headers=other_headers).json()["total"] == 0
    other_eval = test_client.post("/api/v1/license-policies/evaluate", json={
        "project": "lic-app", "version": "1.0"}, headers=other_headers)
    assert other_eval.status_code == 404  # project belongs to another org


def test_audit_chain_covers_license_actions(lic_client):
    test_client, headers, _other, _session = lic_client
    _ingest(test_client, headers)
    test_client.post("/api/v1/license-policies", json={
        "name": "p2", "deny_list": "GPL-3.0-only", "actor": "legal"},
        headers=headers)
    audit = test_client.get("/api/v1/audit", headers=headers).json()
    actions = [row["action"] for row in audit["data"]]
    assert "license.policy_created" in actions
    assert audit["chain_ok"] is True

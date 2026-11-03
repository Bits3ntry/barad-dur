"""BL-090 acceptance: asset snapshots and change detection."""
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
def easm_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/bl90.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    key = create_key(session, org.id, "bl90")
    other_key = create_key(session, other.id, "bl902")
    session.commit()
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key}, {"X-API-Key": other_key})


def _asset(test_client, headers):
    return test_client.post("/api/v1/assets", json={
        "type": "domain", "value": "shop.company.org"},
        headers=headers).json()["data"]


def test_snapshot_history_and_change_detection(easm_client):
    test_client, headers, _other = easm_client
    asset = _asset(test_client, headers)
    first = test_client.post(f"/api/v1/assets/{asset['id']}/snapshots", json={
        "data": {"ip": "203.0.113.10", "tech": ["nginx", "php"], "tls_issuer": "LetsEncrypt"},
        "source": "dns-scan", "actor": "gate"}, headers=headers)
    assert first.status_code == 200, first.text
    second = test_client.post(f"/api/v1/assets/{asset['id']}/snapshots", json={
        "data": {"ip": "203.0.113.11", "tech": ["nginx", "php", "redis"],
                 "tls_issuer": "LetsEncrypt"},
        "source": "dns-scan", "actor": "gate"}, headers=headers)
    assert second.status_code == 200

    listed = test_client.get(f"/api/v1/assets/{asset['id']}/snapshots",
                             headers=headers).json()
    assert listed["total"] == 2

    changes = test_client.get(f"/api/v1/assets/{asset['id']}/changes",
                              headers=headers).json()["data"]
    assert changes["asset"] == "shop.company.org"
    assert changes["snapshots"] == 2
    by_field = {row["field"]: row for row in changes["latest_changes"]}
    assert by_field["ip"]["before"] == "203.0.113.10"
    assert by_field["ip"]["after"] == "203.0.113.11"
    assert "tls_issuer" not in by_field  # unchanged fields stay quiet
    assert len(changes["history"]) == 1


def test_single_snapshot_has_no_changes(easm_client):
    test_client, headers, _other = easm_client
    asset = _asset(test_client, headers)
    test_client.post(f"/api/v1/assets/{asset['id']}/snapshots", json={
        "data": {"ip": "1.2.3.4"}}, headers=headers)
    changes = test_client.get(f"/api/v1/assets/{asset['id']}/changes",
                              headers=headers).json()["data"]
    assert changes["snapshots"] == 1
    assert changes["latest_changes"] == []


def test_tenant_isolation_and_audit(easm_client):
    test_client, headers, other_headers = easm_client
    asset = _asset(test_client, headers)
    test_client.post(f"/api/v1/assets/{asset['id']}/snapshots", json={
        "data": {"ip": "1.2.3.4"}, "actor": "gate"}, headers=headers)
    # Foreign org cannot read or write snapshots of another org's asset.
    assert test_client.get(f"/api/v1/assets/{asset['id']}/snapshots",
                           headers=other_headers).status_code == 404
    assert test_client.post(f"/api/v1/assets/{asset['id']}/snapshots",
                            json={"data": {"ip": "9.9.9.9"}},
                            headers=other_headers).status_code == 404
    audit = test_client.get("/api/v1/audit?action=asset.snapshot",
                            headers=headers).json()
    assert audit["total"] >= 1
    assert audit["chain_ok"] is True

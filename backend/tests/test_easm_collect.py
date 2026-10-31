"""EASM collection: DNS discovery gated by passive_discovery, TLS by active."""
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
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/easm2.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    key = create_key(session, org.id, "easm")
    other_key = create_key(session, other.id, "easm2")
    session.commit()
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key}, {"X-API-Key": other_key})


def _asset(test_client, headers, value="localhost"):
    return test_client.post("/api/v1/assets", json={
        "type": "domain", "value": value}, headers=headers).json()["data"]


def _grant(test_client, headers, value, capability):
    response = test_client.post("/api/v1/authorization/grants", json={
        "principal": "collector", "capabilities": [capability],
        "targets": [{"type": "domain", "value": value}],
        "tools": ["dns-collector"] if capability == "passive_discovery" else ["tls-probe"],
        "issued_by": "santiago", "justification": "easm gate",
        "actor": "santiago"}, headers=headers)
    assert response.status_code in (200, 201), response.text


def test_collect_requires_passive_grant(easm_client):
    test_client, headers, _other = easm_client
    asset = _asset(test_client, headers)
    denied = test_client.post(f"/api/v1/assets/{asset['id']}/collect",
                              json={"actor": "collector"}, headers=headers)
    assert denied.status_code == 403
    assert "not authorized" in denied.json()["detail"]
    snapshots = test_client.get(f"/api/v1/assets/{asset['id']}/snapshots",
                                headers=headers).json()
    assert snapshots["total"] == 0  # nothing was observed or stored


def test_collect_records_dns_snapshot(easm_client):
    test_client, headers, _other = easm_client
    asset = _asset(test_client, headers)
    _grant(test_client, headers, "localhost", "passive_discovery")
    collected = test_client.post(f"/api/v1/assets/{asset['id']}/collect",
                                 json={"actor": "collector"}, headers=headers)
    assert collected.status_code == 200, collected.text
    observation = collected.json()["data"]["observation"]
    assert "dns" in observation
    assert observation["dns"]["ipv4"] or observation["dns"]["ipv6"]
    assert "tls" not in observation  # TLS was not requested

    snapshots = test_client.get(f"/api/v1/assets/{asset['id']}/snapshots",
                                headers=headers).json()
    assert snapshots["total"] == 1
    assert snapshots["data"][0]["source"] == "dns-collector"


def test_tls_probe_needs_active_verification(easm_client):
    test_client, headers, _other = easm_client
    asset = _asset(test_client, headers)
    _grant(test_client, headers, "localhost", "passive_discovery")
    denied = test_client.post(f"/api/v1/assets/{asset['id']}/collect",
                              json={"tls": True, "actor": "collector"},
                              headers=headers)
    assert denied.status_code == 403
    assert "tls probe not authorized" in denied.json()["detail"]
    # the denial must not leave a half-written snapshot behind
    snapshots = test_client.get(f"/api/v1/assets/{asset['id']}/snapshots",
                                headers=headers).json()
    assert snapshots["total"] == 0

    _grant(test_client, headers, "localhost", "active_verification")
    allowed = test_client.post(f"/api/v1/assets/{asset['id']}/collect",
                               json={"tls": True, "actor": "collector"},
                               headers=headers)
    assert allowed.status_code == 200, allowed.text
    tls = allowed.json()["data"]["observation"]["tls"]
    # localhost has no TLS listener: the probe reports a real failure, not fake data
    assert "error" in tls or "subject" in tls


def test_collect_validation_and_isolation(easm_client):
    test_client, headers, other_headers = easm_client
    asset = _asset(test_client, headers)
    _grant(test_client, headers, "localhost", "passive_discovery")
    assert test_client.post(f"/api/v1/assets/{asset['id']}/collect",
                            json={"actor": "collector"},
                            headers=other_headers).status_code == 404
    ip_asset = test_client.post("/api/v1/assets", json={
        "type": "ip", "value": "203.0.113.5"}, headers=headers).json()["data"]
    invalid = test_client.post(f"/api/v1/assets/{ip_asset['id']}/collect",
                               json={"actor": "collector"}, headers=headers)
    assert invalid.status_code == 422
    assert "domain assets only" in invalid.json()["detail"]

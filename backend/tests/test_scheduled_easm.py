"""Scheduled EASM collection (and that scan schedules still behave)."""
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
def easm_sched_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/es.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    key = create_key(session, org.id, "es")
    other_key = create_key(session, other.id, "es2")
    session.commit()
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key}, {"X-API-Key": other_key})


def _asset(test_client, headers, value="localhost"):
    return test_client.post("/api/v1/assets", json={
        "type": "domain", "value": value}, headers=headers).json()["data"]


def _grant(test_client, headers, value):
    response = test_client.post("/api/v1/authorization/grants", json={
        "principal": "collector", "capabilities": ["passive_discovery"],
        "targets": [{"type": "domain", "value": value}],
        "tools": ["dns-collector"], "issued_by": "santiago",
        "justification": "scheduled discovery", "actor": "santiago"},
        headers=headers)
    assert response.status_code in (200, 201), response.text


def _schedule(test_client, headers, asset_id, name="nightly-dns"):
    return test_client.post("/api/v1/orchestration/schedules", json={
        "name": name, "kind": "easm", "asset_id": asset_id,
        "principal": "collector", "interval_minutes": 60, "actor": "santiago",
    }, headers=headers)


def test_scheduled_collection_creates_snapshot(easm_sched_client):
    test_client, headers, _other = easm_sched_client
    asset = _asset(test_client, headers)
    _grant(test_client, headers, "localhost")
    created = _schedule(test_client, headers, asset["id"])
    assert created.status_code == 200, created.text
    assert created.json()["data"]["kind"] == "easm"

    tick = test_client.post("/api/v1/orchestration/schedules/tick",
                            json={"actor": "cron"}, headers=headers).json()["data"]
    assert tick["processed"] == 1
    assert tick["results"][0]["result"] == "collected"
    assert tick["results"][0]["ipv4"] >= 0

    snapshots = test_client.get(f"/api/v1/assets/{asset['id']}/snapshots",
                                headers=headers).json()
    assert snapshots["total"] == 1
    assert snapshots["data"][0]["source"] == "scheduled-collector"
    data = snapshots["data"][0]["data"]
    assert "dns" in data

    # inside the interval the tick must not collect again
    again = test_client.post("/api/v1/orchestration/schedules/tick",
                             json={"actor": "cron"}, headers=headers).json()["data"]
    assert again["processed"] == 0
    snapshots = test_client.get(f"/api/v1/assets/{asset['id']}/snapshots",
                                headers=headers).json()
    assert snapshots["total"] == 1


def test_scheduled_collection_respects_authorization(easm_sched_client):
    test_client, headers, _other = easm_sched_client
    asset = _asset(test_client, headers)
    _schedule(test_client, headers, asset["id"], name="unauthorized-dns")
    tick = test_client.post("/api/v1/orchestration/schedules/tick",
                            json={"actor": "cron"}, headers=headers).json()["data"]
    assert tick["results"][0]["result"] == "denied"
    assert "no active grant" in tick["results"][0]["reason"]
    snapshots = test_client.get(f"/api/v1/assets/{asset['id']}/snapshots",
                                headers=headers).json()
    assert snapshots["total"] == 0  # nothing was collected or stored
    schedule = test_client.get("/api/v1/orchestration/schedules",
                               headers=headers).json()["data"][0]
    assert schedule["last_error"].startswith("denied:")
    assert schedule["due"] is False  # clock advanced anyway


def test_easm_schedule_validation(easm_sched_client):
    test_client, headers, _other = easm_sched_client
    asset = _asset(test_client, headers)
    no_asset = test_client.post("/api/v1/orchestration/schedules", json={
        "name": "no-asset", "kind": "easm", "principal": "collector",
        "actor": "santiago"}, headers=headers)
    assert no_asset.status_code == 422
    bad_kind = test_client.post("/api/v1/orchestration/schedules", json={
        "name": "bad", "kind": "warp", "principal": "collector",
        "actor": "santiago"}, headers=headers)
    assert bad_kind.status_code == 422
    ip_asset = test_client.post("/api/v1/assets", json={
        "type": "ip", "value": "203.0.113.9"}, headers=headers).json()["data"]
    wrong_type = _schedule(test_client, headers, ip_asset["id"], name="ip-dns")
    assert wrong_type.status_code == 422
    # foreign asset is not accepted either
    foreign_asset = test_client.post(
        "/api/v1/assets", json={"type": "domain", "value": "other.dev"},
        headers=_other).json()["data"]
    stolen = _schedule(test_client, headers, foreign_asset["id"], name="stolen")
    assert stolen.status_code == 404

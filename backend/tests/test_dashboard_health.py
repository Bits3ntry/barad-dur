"""Dashboard: scanner execution health and pentest posture."""
import datetime
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
def dash_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/dash2.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    key = create_key(session, org.id, "dash")
    other_key = create_key(session, other.id, "dash2")

    now = models.utcnow()
    session.add_all([
        models.Worker(org_id=org.id, name="healthy", capabilities="[]",
                      registered_at=now, last_heartbeat=now),
        models.Worker(org_id=org.id, name="silent", capabilities="[]",
                      registered_at=now,
                      last_heartbeat=now - datetime.timedelta(minutes=30)),
    ])
    session.add_all([
        models.ScanJob(org_id=org.id, scanner="trivy",
                       capability="vulnerability_analysis", principal="ci",
                       targets="[]", profile="{}", status="succeeded",
                       created_at=now - datetime.timedelta(hours=2),
                       started_at=now - datetime.timedelta(hours=2),
                       finished_at=now - datetime.timedelta(hours=1, minutes=50)),
        models.ScanJob(org_id=org.id, scanner="opengrep",
                       capability="vulnerability_analysis", principal="ci",
                       targets="[]", profile="{}", status="failed",
                       error="authorization revalidation denied",
                       created_at=now - datetime.timedelta(hours=1),
                       finished_at=now - datetime.timedelta(minutes=55)),
        models.ScanJob(org_id=org.id, scanner="trivy",
                       capability="vulnerability_analysis", principal="ci",
                       targets="[]", profile="{}", status="queued",
                       created_at=now),
    ])
    engagement = models.PentestEngagement(
        org_id=org.id, name="Q4", status="active", created_at=now,
        updated_at=now)
    session.add(engagement)
    session.flush()
    session.add(models.PentestFinding(
        org_id=org.id, engagement_id=engagement.id, title="idor",
        severity="HIGH", status="open", reported_by="t", created_at=now,
        updated_at=now))
    session.commit()
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key}, {"X-API-Key": other_key})


def test_orchestration_and_pentest_blocks(dash_client):
    test_client, headers, _other = dash_client
    data = test_client.get("/api/v1/dashboard/summary", headers=headers).json()["data"]
    orchestration = data["orchestration"]
    assert orchestration["workers"]["total"] == 2
    assert orchestration["workers"]["online"] == 1
    assert orchestration["workers"]["stale"] == 1
    assert orchestration["jobs"]["succeeded"] == 1
    assert orchestration["jobs"]["failed"] == 1
    assert orchestration["jobs"]["queued"] == 1
    assert orchestration["last_24h"] == {"succeeded": 1, "failed": 1}
    assert orchestration["avg_duration_s"] == pytest.approx(600.0, rel=0.05)
    assert orchestration["recent_failures"][0]["scanner"] == "opengrep"
    assert "revalidation" in orchestration["recent_failures"][0]["error"]

    pentest = data["pentest"]
    assert pentest["engagements"]["active"] == 1
    assert pentest["findings_open"] == 1
    assert pentest["findings_total"] == 1


def test_blocks_are_tenant_scoped(dash_client):
    test_client, _headers, other_headers = dash_client
    data = test_client.get("/api/v1/dashboard/summary",
                           headers=other_headers).json()["data"]
    assert data["orchestration"]["workers"]["total"] == 0
    assert data["orchestration"]["jobs"]["queued"] == 0
    assert data["pentest"]["findings_total"] == 0

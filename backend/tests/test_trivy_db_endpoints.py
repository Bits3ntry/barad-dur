"""GAP-08: offline Trivy DB updater endpoints.

Regression cover for three failures found live: the status endpoint shipped
without its session dependency (500), `/updates/freshness` was shadowed by
`/updates/{update_id}`, and a missing `trivy` binary surfaced as a 502
instead of an explicit 503.
"""
import datetime
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


@pytest.fixture()
def trivy_env(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/trivy.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "trivy")
    yield TestClient(app), {"X-API-Key": key}, session, org
    session.close()


def test_endpoints_require_auth(trivy_env):
    client, _, _, _ = trivy_env
    assert client.get("/api/v1/easm/trivy-db/updates").status_code == 401
    assert client.get("/api/v1/easm/trivy-db/updates/freshness").status_code == 401


def test_list_is_empty_on_a_fresh_org(trivy_env):
    client, headers, _, _ = trivy_env
    response = client.get("/api/v1/easm/trivy-db/updates", headers=headers)
    assert response.status_code == 200
    assert response.json() == []


def test_freshness_when_no_db_was_ever_published(trivy_env):
    client, headers, _, _ = trivy_env
    response = client.get("/api/v1/easm/trivy-db/updates/freshness", headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["fresh"] is False
    assert body["age_hours"] is None
    assert body["last_successful_at"] is None


def test_freshness_reports_a_recent_publish(trivy_env):
    """Also proves `/updates/freshness` is not shadowed by `/{update_id}`."""
    client, headers, session, org = trivy_env
    published = models.utcnow() - datetime.timedelta(hours=2)
    session.add(models.TrivyDbUpdate(
        org_id=org.id, status="completed", target_filename="trivy.db",
        target_size=1024, target_sha256="a" * 64, header_version="v2026-11-01",
        last_successful_at=published))
    session.commit()

    body = client.get("/api/v1/easm/trivy-db/updates/freshness",
                      headers=headers).json()
    assert body["fresh"] is True
    assert 1.9 < body["age_hours"] < 2.1


def test_status_of_unknown_update_is_404(trivy_env):
    client, headers, _, _ = trivy_env
    response = client.get("/api/v1/easm/trivy-db/updates/does-not-exist",
                          headers=headers)
    assert response.status_code == 404


def test_update_reports_503_when_trivy_is_not_installed(trivy_env, monkeypatch):
    client, headers, _, _ = trivy_env
    monkeypatch.setattr("backend.app.routers.easm_trivy.shutil.which",
                        lambda _name: None)
    response = client.post("/api/v1/easm/trivy-db/updates", headers=headers)
    assert response.status_code == 503
    assert "trivy_unavailable" in response.text


def test_updates_are_tenant_scoped(trivy_env):
    client, headers, session, _ = trivy_env
    other = models.Organization(slug="other", name="Other")
    session.add(other)
    session.flush()
    session.add(models.TrivyDbUpdate(org_id=other.id, status="completed",
                                     target_filename="trivy.db",
                                     last_successful_at=models.utcnow()))
    session.commit()

    assert client.get("/api/v1/easm/trivy-db/updates", headers=headers).json() == []
    freshness = client.get("/api/v1/easm/trivy-db/updates/freshness",
                           headers=headers).json()
    assert freshness["fresh"] is False

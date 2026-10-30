"""B4 acceptance: assets, crt.sh discovery (network mocked), resweep dedup."""
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
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/b4.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "b4")
    session.commit()
    from fastapi.testclient import TestClient

    return TestClient(app), key


H = dict


def test_discovery_then_resweep_and_manual_assets(client, monkeypatch):
    test_client, key = client
    headers = {"X-API-Key": key}
    import backend.app.routers.easm as easm

    monkeypatch.setattr(easm, "crtsh_subdomains",
                        lambda domain, timeout=25.0: ["api.nous.dev", "staging.nous.dev"])
    swept = test_client.post("/api/v1/assets/discover", json={
        "domain": "nous.dev", "actor": "santiago"}, headers=headers).json()
    assert swept["data"] == {"domain": "nous.dev", "created": 2,
                             "refreshed": 0, "total_known": 3}

    again = test_client.post("/api/v1/assets/discover", json={
        "domain": "nous.dev"}, headers=headers).json()
    assert again["data"]["created"] == 0
    assert again["data"]["refreshed"] == 2

    manual = test_client.post("/api/v1/assets", json={
        "type": "ip", "value": "203.0.113.7", "actor": "santiago"}, headers=headers)
    assert manual.status_code == 200, manual.text
    dup = test_client.post("/api/v1/assets", json={
        "type": "ip", "value": "203.0.113.7"}, headers=headers).json()
    assert dup["already_known"] is True

    assets = test_client.get("/api/v1/assets", headers=headers).json()
    assert assets["total"] == 4  # seed + 2 subs + manual ip
    types = {row["type"] for row in assets["data"]}
    assert types == {"domain", "ip"}
    bad = test_client.post("/api/v1/assets", json={
        "type": "galaxy", "value": "banzai"}, headers=headers)
    assert bad.status_code == 422

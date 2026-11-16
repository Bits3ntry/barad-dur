"""Business context: the screen shows what somebody designated, and a search is
how you designate.

Pins the OpenCTEM pattern the owner asked for: the crown-jewel list is the short
list, not the registry — 5 components exist, 1 is a jewel, and the other four are
reachable through `/candidates`, never printed as a wall of undecided rows.
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
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/crown3.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "crown3")
    aurea = models.Project(org_id=org.id, name="AUREA", slug="aurea")
    session.add(aurea)
    session.flush()
    backend = models.ApplicationComponent(org_id=org.id, project_id=aurea.id,
                                          name="Backend", slug="backend", kind="backend")
    web = models.ApplicationComponent(org_id=org.id, project_id=aurea.id,
                                      name="web", slug="web", kind="frontend")
    session.add_all([backend, web])
    session.flush()
    asset = models.Asset(org_id=org.id, type="domain", value="api.aurea.test",
                         source="scope", project_id=aurea.id)
    session.add(asset)
    session.flush()
    deployment = models.Deployment(org_id=org.id, name="Backend · PRO", environment="PRO",
                                   application_component_id=backend.id, status="active")
    session.add(deployment)
    session.flush()
    session.add(models.AssetLink(org_id=org.id, asset_id=asset.id,
                                 entity_type="deployment", entity_id=deployment.id,
                                 relation="serves"))
    session.add(models.Observation(org_id=org.id, asset_id=asset.id, kind="port",
                                   subject="api.aurea.test", source="shauron",
                                   coverage="full", value={"port": 443, "state": "open"}))
    session.commit()
    from fastapi.testclient import TestClient

    return TestClient(app), {"X-API-Key": key}, session, org, backend, web


def _designate(client, headers, component_id, level="crown"):
    return client.patch(f"/api/v1/business-context/components/{component_id}",
                        json={"criticality": level, "actor": "santiago"},
                        headers=headers)


def test_the_list_is_the_short_list_not_the_registry(env):
    client, headers, _session, _org, backend, _web = env
    empty = client.get("/api/v1/business-context", headers=headers).json()
    assert empty["data"] == []
    assert empty["summary"]["registered"] == 2
    assert empty["summary"]["crown"] == 0

    _designate(client, headers, backend.id)
    listing = client.get("/api/v1/business-context", headers=headers).json()
    assert [row["slug"] for row in listing["data"]] == ["backend"]
    assert listing["summary"]["crown"] == 1
    assert listing["summary"]["jewel_assets"] == 1


def test_the_picker_searches_the_components_nobody_designated(env):
    client, headers, _session, _org, backend, _web = env
    picked = client.get("/api/v1/business-context/candidates", headers=headers).json()
    assert {row["slug"] for row in picked["data"]} == {"backend", "web"}
    assert picked["data"][0]["project_name"] == "AUREA"

    _designate(client, headers, backend.id)
    after = client.get("/api/v1/business-context/candidates", headers=headers).json()
    assert [row["slug"] for row in after["data"]] == ["web"]

    searched = client.get("/api/v1/business-context/candidates?q=back",
                          headers=headers).json()
    assert searched["data"] == [], "a designated component is not a candidate"


def test_the_counts_hang_off_the_component(env):
    client, headers, _session, _org, backend, _web = env
    _designate(client, headers, backend.id)
    row = client.get("/api/v1/business-context", headers=headers).json()["data"][0]
    assert row["deployments"] == 1
    assert row["environments"] == ["PRO"]
    assert row["assets"] == 1
    assert row["observed_assets"] == 1


def test_a_withdrawn_judgement_leaves_the_short_list(env):
    client, headers, _session, _org, backend, _web = env
    _designate(client, headers, backend.id)
    cleared = client.patch(f"/api/v1/business-context/components/{backend.id}",
                           json={"criticality": None, "actor": "santiago"},
                           headers=headers)
    assert cleared.json()["data"]["criticality"] == "unclassified"
    listing = client.get("/api/v1/business-context", headers=headers).json()
    assert listing["data"] == []
    assert listing["summary"]["crown"] == 0


def test_the_whole_registry_is_one_flag_away(env):
    client, headers, _session, _org, _backend, _web = env
    everything = client.get("/api/v1/business-context?all=1", headers=headers).json()
    assert {row["slug"] for row in everything["data"]} == {"backend", "web"}
    assert all(row["criticality"] == "unclassified" for row in everything["data"])


def test_an_unknown_level_is_refused(env):
    client, headers, _session, _org, backend, _web = env
    bad = client.patch(f"/api/v1/business-context/components/{backend.id}",
                       json={"criticality": "critical-ish"}, headers=headers)
    assert bad.status_code == 422

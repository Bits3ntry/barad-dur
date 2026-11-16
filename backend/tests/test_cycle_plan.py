"""The cycle binds everything: jewels, their techniques, the profiles that chose them.

This is the join the owner asked for. A cycle declares crown jewels and attacker
profiles; the plan derives the techniques from the jewels' threat models, adds the
ones a profile names, and scores each as ready / blocked / untestable against the
grants that exist. Activation freezes that plan next to the membership.
"""
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
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/plan.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "plan")
    project = models.Project(org_id=org.id, name="AUREA", slug="aurea")
    session.add(project)
    session.flush()
    jewel = models.ApplicationComponent(org_id=org.id, project_id=project.id,
                                        name="Backend", slug="backend",
                                        kind="backend", criticality="crown")
    session.add(jewel)
    session.flush()
    asset = models.Asset(org_id=org.id, type="domain", value="api.aurea.test",
                         source="scope", project_id=project.id)
    session.add(asset)
    session.flush()
    session.add(models.AssetLink(org_id=org.id, asset_id=asset.id,
                                 entity_type="application_component",
                                 entity_id=jewel.id, relation="serves"))
    session.add_all([
        models.AttackTechnique(id="T1046", name="Network Service Discovery",
                               tactic="Discovery", capability="active_verification"),
        models.AttackTechnique(id="T1566", name="Phishing", tactic="Initial Access",
                               capability=None),
        models.AttackTechnique(id="T1190", name="Exploit Public-Facing Application",
                               tactic="Initial Access", capability="intrusive_testing"),
    ])
    session.add_all([
        models.ThreatEntry(org_id=org.id, component_id=jewel.id, technique_id="T1046"),
        models.ThreatEntry(org_id=org.id, component_id=jewel.id, technique_id="T1566"),
    ])
    profile = models.AttackerProfile(org_id=org.id, name="external",
                                     origin="external",
                                     techniques='["T1190"]')
    session.add(profile)
    session.commit()
    from fastapi.testclient import TestClient

    return TestClient(app), {"X-API-Key": key}, session, org, jewel, profile, asset


def _cycle(client, headers, jewel, profile):
    return client.post("/api/v1/cycles", json={
        "name": "Backend campaign", "kind": "campaign", "actor": "santiago",
        "selection": {"components": [jewel.id]},
        "charter": {"profile_ids": [profile.id]},
    }, headers=headers).json()["data"]


def test_the_plan_joins_jewel_techniques_and_profile(env):
    client, headers, _session, _org, jewel, profile, _asset = env
    cycle = _cycle(client, headers, jewel, profile)
    preview = client.post(f"/api/v1/cycles/{cycle['id']}/preview", headers=headers).json()["data"]
    plan = preview["plan"]
    assert [row["name"] for row in plan["jewels"]] == ["Backend"]
    assert {row["id"] for row in plan["techniques"]} == {"T1046", "T1566", "T1190"}
    assert plan["coverage"] == {"declared": 3, "ready": 0, "blocked": 2, "untestable": 1}
    assert plan["scope"]["assets"] == 1
    assert len(plan["gaps"]) == 3, plan["gaps"]


def test_a_grant_turns_the_matching_technique_ready(env):
    client, headers, session, org, jewel, profile, _asset = env
    now = models.utcnow()
    session.add(models.ScanGrant(
        org_id=org.id, principal="collector", capabilities="active_verification",
        level="simple", issued_by="tester", justification="test",
        policy_version=1, status="active", valid_from=now,
        valid_until=now + datetime.timedelta(days=7)))
    session.commit()
    cycle = _cycle(client, headers, jewel, profile)
    plan = client.post(f"/api/v1/cycles/{cycle['id']}/preview",
                       headers=headers).json()["data"]["plan"]
    assert plan["coverage"]["ready"] == 1
    state = {row["id"]: row["state"] for row in plan["techniques"]}
    assert state["T1046"] == "ready"
    assert state["T1190"] == "blocked"
    assert plan["runnable"] is False


def test_activating_freezes_the_plan_next_to_the_membership(env):
    client, headers, _session, _org, jewel, profile, _asset = env
    cycle = _cycle(client, headers, jewel, profile)
    activated = client.post(f"/api/v1/cycles/{cycle['id']}/activate", headers=headers)
    assert activated.status_code == 200, activated.text
    detail = client.get(f"/api/v1/cycles/{cycle['id']}", headers=headers).json()["data"]
    frozen = detail["snapshot"]["plan"]
    assert [row["name"] for row in frozen["jewels"]] == ["Backend"]
    assert frozen["coverage"]["declared"] == 3
    membership = {row["entity_type"] for row in detail["membership"]}
    assert membership == {"component", "asset"}


def test_a_component_outside_the_org_is_reported_as_a_gap(env):
    client, headers, _session, _org, jewel, profile, _asset = env
    cycle = client.post("/api/v1/cycles", json={
        "name": "Ghost", "kind": "campaign",
        "selection": {"components": [jewel.id, "00000000-0000-0000-0000-000000000000"]},
    }, headers=headers).json()["data"]
    preview = client.post(f"/api/v1/cycles/{cycle['id']}/preview",
                          headers=headers).json()["data"]
    assert any("does not exist" in gap for gap in preview["gaps"])


def test_the_plan_can_be_previewed_before_the_cycle_exists(env):
    """The create dialog needs the coverage while filling the form."""
    client, headers, _session, _org, jewel, profile, _asset = env
    plan = client.post("/api/v1/threat-model/plan", json={
        "components": [jewel.id], "profile_ids": [profile.id],
    }, headers=headers).json()["data"]
    assert plan["coverage"]["declared"] == 3
    assert plan["scope"]["assets"] == 1


def test_the_scope_is_written_by_searching(env):
    """An operator knows the host or the repo, not the uuid."""
    client, headers, session, org, _jewel, _profile, _asset = env
    session.add(models.Repository(org_id=org.id, provider="gitea",
                                  name="bitsentry/aurea-server",
                                  remote_url="https://git.test/bitsentry/aurea-server"))
    session.commit()
    found = client.get("/api/v1/cycles/scope-search?q=aurea", headers=headers).json()
    assert [row["slug"] for row in found["projects"]] == ["aurea"]
    assert any("aurea" in row["label"] for row in found["repositories"])
    assert all("aurea" in row["label"] for row in found["assets"])


def test_a_single_asset_or_repository_can_be_the_scope(env):
    client, headers, session, org, _jewel, _profile, asset = env
    repository = models.Repository(org_id=org.id, provider="gitea",
                                   name="bitsentry/aurea-server",
                                   remote_url="https://git.test/aurea-server")
    session.add(repository)
    session.commit()
    cycle = client.post("/api/v1/cycles", json={
        "name": "One host", "kind": "campaign",
        "selection": {"assets": [asset.id], "repositories": [repository.id]},
    }, headers=headers).json()["data"]
    preview = client.post(f"/api/v1/cycles/{cycle['id']}/preview",
                          headers=headers).json()["data"]
    assert preview["members"] == 2
    activated = client.post(f"/api/v1/cycles/{cycle['id']}/activate", headers=headers)
    assert activated.status_code == 200, activated.text
    detail = client.get(f"/api/v1/cycles/{cycle['id']}", headers=headers).json()["data"]
    assert {row["entity_type"] for row in detail["membership"]} == {"asset", "repository"}

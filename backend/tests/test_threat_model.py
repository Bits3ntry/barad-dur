"""Threat model: techniques per crown jewel, scored by what we can actually test.

The arithmetic under test: declared / testable / ready / blocked / untestable, with
`ran` unmeasured instead of zero, and profiles that are org-scoped bundles of
techniques rather than a free-text field on a cycle.
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
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/tm.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "tm")
    project = models.Project(org_id=org.id, name="AUREA", slug="aurea")
    session.add(project)
    session.flush()
    jewel = models.ApplicationComponent(org_id=org.id, project_id=project.id,
                                        name="Backend", slug="backend", kind="backend",
                                        criticality="crown")
    other = models.ApplicationComponent(org_id=org.id, project_id=project.id,
                                        name="web", slug="web", kind="frontend")
    session.add_all([jewel, other])
    session.add_all([
        models.AttackTechnique(id="T1046", name="Network Service Discovery",
                               tactic="Discovery", capability="active_verification"),
        models.AttackTechnique(id="T1566", name="Phishing", tactic="Initial Access",
                               capability=None),
        models.AttackTechnique(id="T1195.002", name="Compromise Software Supply Chain",
                               tactic="Initial Access", capability="code_analysis"),
    ])
    session.commit()
    from fastapi.testclient import TestClient

    return TestClient(app), {"X-API-Key": key}, session, org, jewel, other


def _grant(session, org, capabilities="active_verification"):
    import datetime
    now = models.utcnow()
    grant = models.ScanGrant(
        org_id=org.id, principal="collector", capabilities=capabilities, level="simple",
        issued_by="tester", justification="test", policy_version=1, status="active",
        valid_from=now, valid_until=now + datetime.timedelta(days=30))
    session.add(grant)
    session.commit()
    return grant


def test_only_crown_jewels_are_offered(env):
    client, headers, _session, _org, jewel, _other = env
    body = client.get("/api/v1/threat-model/crown-jewels", headers=headers).json()
    assert [row["slug"] for row in body["data"]] == ["backend"]
    assert body["data"][0]["techniques"] == 0


def test_declaring_techniques_is_per_jewel_and_idempotent(env):
    client, headers, _session, _org, jewel, _other = env
    first = client.post("/api/v1/threat-model/entries",
                        json={"component_id": jewel.id, "technique_id": "T1046",
                              "reason": "exposed admin panel"}, headers=headers)
    assert first.status_code == 201, first.text
    assert first.json()["created"] is True
    again = client.post("/api/v1/threat-model/entries",
                        json={"component_id": jewel.id, "technique_id": "T1046"},
                        headers=headers)
    assert again.status_code == 200
    assert again.json()["created"] is False

    client.post("/api/v1/threat-model/entries",
                json={"component_id": jewel.id, "technique_id": "T1566"},
                headers=headers)
    model = client.get(f"/api/v1/threat-model?jewel={jewel.id}", headers=headers).json()
    assert model["coverage"]["declared"] == 2
    assert model["coverage"]["testable"] == 1
    assert model["coverage"]["untestable"] == 1
    assert model["coverage"]["ran"] is None, "unmeasured is not zero"
    states = {row["technique_id"]: row["state"] for row in model["entries"]}
    assert states == {"T1046": "blocked", "T1566": "untestable"}


def test_a_grant_turns_a_technique_ready(env):
    client, headers, session, org, jewel, _other = env
    _grant(session, org, "active_verification")
    client.post("/api/v1/threat-model/entries",
                json={"component_id": jewel.id, "technique_id": "T1046"}, headers=headers)
    model = client.get(f"/api/v1/threat-model?jewel={jewel.id}", headers=headers).json()
    assert model["coverage"]["ready"] == 1
    assert model["entries"][0]["state"] == "ready"
    assert model["granted_capabilities"] == ["active_verification"]


def test_the_catalog_excludes_what_the_jewel_already_declares(env):
    client, headers, _session, _org, jewel, _other = env
    client.post("/api/v1/threat-model/entries",
                json={"component_id": jewel.id, "technique_id": "T1046"}, headers=headers)
    catalog = client.get(f"/api/v1/threat-model/catalog?jewel={jewel.id}",
                         headers=headers).json()["data"]
    assert {row["id"] for row in catalog} == {"T1566", "T1195.002"}
    everything = client.get("/api/v1/threat-model/catalog", headers=headers).json()["data"]
    assert {row["id"] for row in everything} == {"T1046", "T1566", "T1195.002"}


def test_a_technique_outside_the_catalogue_is_refused(env):
    client, headers, _session, _org, jewel, _other = env
    refused = client.post("/api/v1/threat-model/entries",
                          json={"component_id": jewel.id, "technique_id": "T9999"},
                          headers=headers)
    assert refused.status_code == 404


def test_profiles_are_org_scoped_bundles_of_techniques(env):
    client, headers, _session, _org, _jewel, _other = env
    created = client.post("/api/v1/threat-model/profiles",
                          json={"name": "opportunistic external",
                                "description": "scans what is reachable",
                                "origin": "external",
                                "tools": ["nmap", "commodity"],
                                "techniques": ["T1046", "T1195.002"],
                                "actor": "santiago"}, headers=headers)
    assert created.status_code == 201, created.text
    body = created.json()["data"]
    assert body["techniques"] == ["T1046", "T1195.002"]
    assert body["tools"] == ["nmap", "commodity"]
    assert body["origin"] == "external"

    duplicate = client.post("/api/v1/threat-model/profiles",
                            json={"name": "opportunistic external"}, headers=headers)
    assert duplicate.status_code == 409

    listed = client.get("/api/v1/threat-model", headers=headers).json()["profiles"]
    assert [row["name"] for row in listed] == ["opportunistic external"]
    assert listed[0]["origin"] == "external" and listed[0]["tools"] == ["nmap", "commodity"]

    bad_origin = client.post("/api/v1/threat-model/profiles",
                             json={"name": "x", "origin": "hired"}, headers=headers)
    assert bad_origin.status_code == 422

    removed = client.delete(f"/api/v1/threat-model/profiles/{created.json()['data']['id']}",
                            headers=headers)
    assert removed.status_code == 200
    assert client.get("/api/v1/threat-model", headers=headers).json()["profiles"] == []

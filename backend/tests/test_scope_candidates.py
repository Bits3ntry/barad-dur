"""Declaring scope by picking what already exists.

A scope list and an inventory are two registries of the same hosts, so declaring
by typing a value is how one target ends up recorded twice — once as an asset,
once as a rule spelled slightly differently. The candidates endpoint answers over
what the estate already holds (assets) and what an active grant already names
(patterns included), with the level that covers each one and whether it is
already declared.
"""
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from starlette.testclient import TestClient

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import authorization, models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/cand.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "candidates")
    project = models.Project(org_id=org.id, name="AUREA", slug="aurea")
    session.add(project)
    session.flush()

    asset = models.Asset(org_id=org.id, type="domain", value="api.aurea.example",
                         source="manual", project_id=project.id)
    session.add(asset)
    session.flush()

    grant, _ = authorization.request_grant(session, org.id, asset, "tester")
    grant.status = "active"
    grant.capabilities = "passive_discovery,active_verification"
    grant.level = "simple"
    grant.valid_until = models.utcnow() + timedelta(days=30)
    grant.approved_by = "admin"

    # A granted pattern has no asset row of its own: `*.aurea.example` is a rule.
    pattern = models.ScanGrant(
        org_id=org.id, principal="console", capabilities="passive_discovery",
        level="simple", issued_by="admin", justification="subtree",
        policy_version=1, status="active", source="manual",
        valid_from=models.utcnow(), valid_until=models.utcnow() + timedelta(days=30))
    session.add(pattern)
    session.flush()
    session.add(models.ScanGrantTarget(
        grant_id=pattern.id, target_type="wildcard_domain",
        target_value="*.aurea.example"))
    session.commit()
    yield TestClient(app), {"X-API-Key": key}, session
    session.close()


def test_candidates_names_the_grant_that_already_covers_the_host(client):
    test_client, headers, _session = client
    body = test_client.get("/api/v1/scope/candidates?q=aurea",
                           headers=headers).json()
    rows = {row["value"]: row for row in body["data"]}
    assert "api.aurea.example" in rows
    host = rows["api.aurea.example"]
    assert host["in_scope"] is False
    assert host["asset_id"]
    assert host["project"] == "AUREA"
    assert host["authorized"]["level"] == "simple"
    assert host["authorized"]["valid_until"]


def test_candidates_includes_a_granted_pattern_with_no_asset(client):
    test_client, headers, _session = client
    rows = {row["value"]: row
            for row in test_client.get("/api/v1/scope/candidates?q=aurea",
                                       headers=headers).json()["data"]}
    pattern = rows["*.aurea.example"]
    assert pattern["source"] == "grant"
    assert pattern["asset_id"] is None
    assert pattern["authorized"]["level"] == "simple"


def test_a_declared_target_comes_back_as_already_in_scope(client):
    test_client, headers, _session = client
    declared = test_client.post("/api/v1/scope/targets", headers=headers, json={
        "target_type": "domain", "value": "api.aurea.example",
        "capabilities": ["passive_discovery"], "actor": "console"})
    assert declared.status_code == 200, declared.text

    rows = {row["value"]: row
            for row in test_client.get("/api/v1/scope/candidates?q=api.aurea",
                                       headers=headers).json()["data"]}
    host = rows["api.aurea.example"]
    assert host["in_scope"] is True
    assert host["scope_target_id"] == declared.json()["data"]["id"]


def test_a_query_shorter_than_two_characters_answers_nothing(client):
    test_client, headers, _session = client
    body = test_client.get("/api/v1/scope/candidates?q=a", headers=headers).json()
    assert body["data"] == []

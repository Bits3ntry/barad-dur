"""v0 scope: declared limits, wildcard semantics, capability and asset linking.

The spec is explicit that a `*.domain` row is a rule/seed, not a host, and that
the scope engine must not silently adopt someone else's semantics. These tests
are where those sentences become executable.
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
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/scope.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="bitsentry", name="Bitsentry")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    key = create_key(session, org.id, "scope")
    other_key = create_key(session, other.id, "scope-other")
    session.commit()
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key}, {"X-API-Key": other_key})


def _add(test_client, headers, **payload):
    payload.setdefault("actor", "tester")
    response = test_client.post("/api/v1/scope/targets", json=payload, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()["data"]


def _check(test_client, headers, value, target_type=None, capability=None):
    body = {"value": value, "target_type": target_type, "capability": capability}
    response = test_client.post("/api/v1/scope/check", json=body, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()["data"]


def test_wildcard_is_a_rule_not_a_host(client):
    test_client, headers, _other = client
    rule = _add(test_client, headers, target_type="domain", value="*.bitsentry.xyz",
                reason="company domains", owner="ana@bitsentry.xyz")
    assert rule["is_pattern"] is True
    assert rule["asset"] is None
    assert rule["capabilities"] == ["passive_discovery"]

    assets = test_client.get("/api/v1/assets", headers=headers).json()
    assert assets["total"] == 0, "a pattern must not invent an asset"

    assert _check(test_client, headers, "api-aurea.bitsentry.xyz",
                  "domain", "passive_discovery")["allowed"] is True
    assert _check(test_client, headers, "a.b.bitsentry.xyz",
                  "domain", "passive_discovery")["allowed"] is True
    apex = _check(test_client, headers, "bitsentry.xyz", "domain", "passive_discovery")
    assert apex["allowed"] is False, "the apex is a separate authorization"

    patched = test_client.patch(f"/api/v1/scope/targets/{rule['id']}", json={
        "include_apex": True, "actor": "tester"}, headers=headers).json()["data"]
    assert patched["include_apex"] is True
    assert _check(test_client, headers, "bitsentry.xyz",
                  "domain", "passive_discovery")["allowed"] is True


def test_concrete_target_links_the_canonical_asset(client):
    test_client, headers, _other = client
    added = _add(test_client, headers, target_type="domain",
                 value="API-Aurea.bitsentry.xyz.", reason="product API")
    assert added["value"] == "api-aurea.bitsentry.xyz"
    assert added["asset"]["source"] == "scope"

    assets = test_client.get("/api/v1/assets?q=api-aurea", headers=headers).json()
    assert assets["total"] == 1
    assert assets["data"][0]["source"] == "scope"
    assert assets["data"][0]["id"] == added["asset"]["id"]

    again = test_client.post("/api/v1/scope/targets", json={
        "target_type": "domain", "value": "api-aurea.bitsentry.xyz"}, headers=headers).json()
    assert again["already_known"] is True
    assert test_client.get("/api/v1/assets", headers=headers).json()["total"] == 1


def test_url_semantics_are_a_scheme_host_and_path_prefix(client):
    test_client, headers, _other = client
    _add(test_client, headers, target_type="url", value="https://api.bitsentry.xyz/v1/")
    assert _check(test_client, headers, "https://api.bitsentry.xyz/v1/orders",
                  capability="passive_discovery")["allowed"] is True
    assert _check(test_client, headers, "https://api.bitsentry.xyz/v10",
                  capability="passive_discovery")["allowed"] is False
    assert _check(test_client, headers, "http://api.bitsentry.xyz/v1",
                  capability="passive_discovery")["allowed"] is False
    rejected = test_client.post("/api/v1/scope/targets", json={
        "target_type": "url", "value": "https://api.bitsentry.xyz/v1?token=1"}, headers=headers)
    assert rejected.status_code == 422


def test_exclusions_win_over_wildcards_and_keep_inventory(client):
    test_client, headers, _other = client
    _add(test_client, headers, target_type="domain", value="*.bitsentry.xyz")
    _add(test_client, headers, target_type="domain", value="api.bitsentry.xyz")
    excluded = test_client.post("/api/v1/scope/exclusions", json={
        "target_type": "domain", "value": "*.legacy.bitsentry.xyz",
        "reason": "third party operates it", "actor": "tester"}, headers=headers)
    assert excluded.status_code == 200, excluded.text

    decision = _check(test_client, headers, "old.legacy.bitsentry.xyz",
                      "domain", "passive_discovery")
    assert decision["allowed"] is False
    assert decision["excluded_by"]["reason"] == "third party operates it"

    resolved = test_client.get("/api/v1/scope/resolved", headers=headers).json()
    assert resolved["excluded_count"] == 1
    assert {row["value"] for row in resolved["data"]} == {"*.bitsentry.xyz",
                                                         "api.bitsentry.xyz"}

    # Excluding never deletes inventory or the scope row it was declared from.
    assert test_client.get("/api/v1/assets", headers=headers).json()["total"] == 1


def test_capabilities_are_explicit_and_cloud_accounts_grant_nothing(client):
    test_client, headers, _other = client
    repo = _add(test_client, headers, target_type="repository", value="bitsentry/aurea")
    assert repo["capabilities"] == ["code_analysis"]
    assert _check(test_client, headers, "bitsentry/aurea", "repository",
                  "code_analysis")["allowed"] is True
    assert _check(test_client, headers, "bitsentry/aurea", "repository",
                  "passive_discovery")["allowed"] is False

    domain = _add(test_client, headers, target_type="domain", value="aurea.example")
    assert _check(test_client, headers, "aurea.example", "domain",
                  "active_verification")["allowed"] is False
    patched = test_client.patch(f"/api/v1/scope/targets/{domain['id']}", json={
        "capabilities": ["passive_discovery", "active_verification"]}, headers=headers)
    assert patched.status_code == 200
    assert _check(test_client, headers, "aurea.example", "domain",
                  "active_verification")["allowed"] is True

    cloud = test_client.post("/api/v1/scope/targets", json={
        "target_type": "cloud_account", "value": "aws:123456789012"}, headers=headers)
    assert cloud.status_code == 200
    assert cloud.json()["data"]["capabilities"] == []
    denied = test_client.post("/api/v1/scope/targets", json={
        "target_type": "cloud_account", "value": "aws:999",
        "capabilities": ["passive_discovery"]}, headers=headers)
    assert denied.status_code == 422

    assert test_client.post("/api/v1/scope/check", json={
        "value": "aws:123456789012", "capability": "nonsense"}, headers=headers).status_code == 422


def test_validity_and_disable_stop_authorizing_without_losing_history(client):
    test_client, headers, _other = client
    target = _add(test_client, headers, target_type="domain", value="old.bitsentry.xyz",
                  valid_until="2020-01-01T00:00:00+00:00")
    assert target["status"] == "expired"
    assert _check(test_client, headers, "old.bitsentry.xyz",
                  "domain", "passive_discovery")["allowed"] is False

    current = _add(test_client, headers, target_type="domain", value="api.bitsentry.xyz")
    disabled = test_client.delete(f"/api/v1/scope/targets/{current['id']}?actor=tester",
                                  headers=headers)
    assert disabled.status_code == 200
    assert disabled.json()["data"]["status"] == "disabled"
    assert _check(test_client, headers, "api.bitsentry.xyz",
                  "domain", "passive_discovery")["allowed"] is False

    rows = test_client.get("/api/v1/scope/targets", headers=headers).json()
    assert rows["total"] == 2, "disabling keeps the declaration"

    history = test_client.get("/api/v1/activity?resource_type=scope_target",
                              headers=headers).json()["data"]
    actions = {row["action"] for row in history}
    assert {"scope.target_added", "scope.target_disabled"} <= actions


def test_scope_is_isolated_between_organizations(client):
    test_client, headers, other_headers = client
    target = _add(test_client, headers, target_type="domain", value="api.bitsentry.xyz")
    assert test_client.get("/api/v1/scope/targets",
                           headers=other_headers).json()["total"] == 0
    assert test_client.patch(f"/api/v1/scope/targets/{target['id']}", json={
        "owner": "intruder"}, headers=other_headers).status_code == 404
    assert test_client.delete(f"/api/v1/scope/targets/{target['id']}",
                              headers=other_headers).status_code == 404
    decision = _check(test_client, other_headers, "api.bitsentry.xyz",
                      "domain", "passive_discovery")
    assert decision["allowed"] is False

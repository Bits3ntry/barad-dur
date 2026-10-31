"""Console-round backend contracts: conditions must deny, server filters."""
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
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/ui.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    key = create_key(session, org.id, "ui")
    other_key = create_key(session, other.id, "ui2")
    session.commit()
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key}, {"X-API-Key": other_key})


def _grant_simple(client, headers, conditions=None):
    test_client, headers, _ = client
    payload = {
        "principal": "runner-x",
        "capabilities": ["intrusive_testing"],
        "targets": [{"type": "domain", "value": "app.company.org"}],
        "issued_by": "santiago",
        "justification": "console round grant",
        "hours": 24,
    }
    if conditions is not None:
        payload["conditions"] = conditions
    return test_client.post("/api/v1/authorization/grants", json=payload,
                            headers=headers)


def _authorize(client, headers, targets=(("domain", "app.company.org"),), **kw):
    test_client, headers, _ = client
    return test_client.post("/api/v1/authorization/authorize", json={
        "principal": "runner-x", "capability": "intrusive_testing",
        "targets": [{"type": t, "value": v} for t, v in targets], **kw},
        headers=headers)


def test_unsupported_conditions_deny(client):
    """A grant with conditions is NEVER silently treated as unconditional."""
    test_client, headers, _ = client
    _grant_simple(client, headers, conditions={"requires_maintenance_window": True})
    denied = _authorize(client, headers)
    body = denied.json()
    assert body["decision"] == "deny"
    assert "conditions" in body["reason"]


def test_conditional_plus_unconditional_grant_allows(client):
    test_client, headers, _ = client
    _grant_simple(client, headers, conditions={"should_become_supported": 1})
    # A second, condition-free grant still allows (rules engine remains usable).
    test_client.post("/api/v1/authorization/grants", json={
        "principal": "runner-x", "capabilities": ["intrusive_testing"],
        "targets": [{"type": "domain", "value": "app.company.org"}],
        "issued_by": "santiago", "justification": "unconditional fallback",
        "hours": 24}, headers=headers)
    allow = _authorize(client, headers)
    assert allow.json()["decision"] == "allow"


def test_grant_filters(client):
    test_client, headers, _ = client
    _grant_simple(client, headers)
    test_client.post("/api/v1/authorization/grants", json={
        "principal": "github-action-ci", "capabilities": ["passive_discovery"],
        "targets": [{"type": "domain", "value": "docs.company.org"}],
        "issued_by": "santiago", "justification": "continuous passive only",
        "hours": 24}, headers=headers)
    by_principal = test_client.get(
        "/api/v1/authorization/grants?principal=github", headers=headers).json()
    assert by_principal["total"] == 1
    assert by_principal["data"][0]["principal"] == "github-action-ci"
    by_capability = test_client.get(
        "/api/v1/authorization/grants?capability=passive_discovery",
        headers=headers).json()
    assert by_capability["total"] == 1
    by_target = test_client.get(
        "/api/v1/authorization/grants?target=docs.", headers=headers).json()
    assert by_target["total"] == 1
    assert by_target["data"][0]["targets"][0]["value"] == "docs.company.org"


def test_audit_filters_and_policies(client):
    test_client, headers, _ = client
    _authorize(client, headers)
    audit = test_client.get(
        "/api/v1/audit?action=authorization.decision", headers=headers).json()
    assert audit["total"] >= 1
    assert "[policy v1]" in audit["data"][0]["detail"]
    empty_window = test_client.get(
        "/api/v1/audit?until=2001-01-01T00:00:00Z", headers=headers).json()
    assert empty_window["total"] == 0 and empty_window["chain_ok"] is True


def test_tenant_isolation_on_authorization_endpoints(client):
    test_client, headers, other_headers = client
    _grant_simple(client, headers)
    other = test_client.get("/api/v1/authorization/grants", headers=other_headers)
    assert other.json()["total"] == 0
    # The other org's key cannot even see or revoke the grant id.
    grant_id = test_client.get("/api/v1/authorization/grants",
                               headers=headers).json()["data"][0]["id"]
    miss = test_client.post(f"/api/v1/authorization/grants/{grant_id}/revoke",
                            json={"reason": "foreign removal attempt",
                                  "actor": "intruder"}, headers=other_headers)
    assert miss.status_code == 404

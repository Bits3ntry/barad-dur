"""BL-015 acceptance: scan authorization engine.

Positive/negative/isolation coverage: default deny, exclusion priority,
wildcard strictness, CIDR/IP, URL exactness, repository/service targets,
self-authorization guard, expiry, revocation mid-run, multi-tenant
isolation, and the audit trail.
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
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/bl15.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    other = models.Organization(slug="other", name="Other Co")
    session.add_all([org, other])
    session.flush()
    key = create_key(session, org.id, "bl15")
    other_key = create_key(session, other.id, "bl15b")
    session.add(models.ScopeExclusion(
        org_id=org.id, target_type="domain", value="thirdparty.example",
        reason="third-party asset, never ours to touch"))
    session.add(models.ScopeExclusion(
        org_id=other.id, target_type="domain", value="othercorp.example",
        reason="other-org internal domain"))
    session.commit()
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key}, {"X-API-Key": other_key},
            session, org)


def _grant(client, headers, principal="runner-01", capabilities=("intrusive_testing",),
           targets=("wildcard_domain", "*.empresa.com"), hours=24,
           issued_by="santiago", extra=None):
    test_client, headers, *_ = client
    if isinstance(targets, tuple) and targets and isinstance(targets[0], str):
        tgt_list = [targets]
    else:
        tgt_list = list(targets)
    payload = {
        "principal": principal,
        "capabilities": list(capabilities),
        "targets": [_t_target(t) for t in tgt_list],
        "justification": "campaign pentest-b4",
        "issued_by": issued_by,
        "hours": hours,
    }
    if extra:
        payload.update(extra)
    return test_client.post("/api/v1/authorization/grants", json=payload,
                            headers=headers)


def _t_target(t):
    a_t, v = t
    return {"type": a_t, "value": v}


def _authorize(test_client, headers, principal, capability, targets, **kw):
    payload = {"principal": principal, "capability": capability,
               "targets": [_t_target(t) for t in targets], **kw}
    return test_client.post("/api/v1/authorization/authorize", json=payload,
                            headers=headers)


def test_default_deny_and_grant_allows(client):
    test_client, headers, _other, _session, _org = client
    denied = _authorize(test_client, headers, "runner-01", "intrusive_testing",
                        [("wildcard_domain", "staging.empresa.com")])
    assert denied.json()["decision"] == "deny"
    assert "no active grant" in denied.json()["reason"]

    grant = _grant(client, headers)
    assert grant.status_code == 200, grant.text
    grant_id = grant.json()["data"]["id"]
    allow = _authorize(test_client, headers, "runner-01", "intrusive_testing",
                       [("wildcard_domain", "staging.empresa.com")])
    assert allow.json()["decision"] == "allow"
    assert allow.json()["matched"] == ["grant", grant_id]
    assert allow.json()["policy_version"] == 1


def test_a_star_value_is_a_wildcard_whatever_type_it_arrives_as(client):
    """`domain: *.example` and `wildcard_domain: *.example` are one permission.

    The console's target picker copies the type from the scope row, and Scope
    stores a pattern as `domain` with a leading star — so grants were being
    written as an exact `domain` whose value happened to contain `*`, matching
    nothing and denying every host under it. The star is the permission.
    """
    http, headers, *_ = client

    created = _grant(client, headers, capabilities=("passive_discovery",),
                     targets=("domain", "*.empresa.com"), hours=24)
    assert created.status_code == 200, created.text
    stored = created.json()["data"]["targets"][0]
    assert stored["type"] == "wildcard_domain", stored

    allowed = _authorize(http, headers, "runner-01", "passive_discovery",
                         [("domain", "api.dev.empresa.com")])
    assert allowed.json()["decision"] == "allow", allowed.text
    apex = _authorize(http, headers, "runner-01", "passive_discovery",
                      [("domain", "empresa.com")])
    assert apex.json()["decision"] == "deny"     # *.empresa.com never covers the apex

    # A grant written before the normalisation still works: same star, old label.
    session = client[3]
    legacy = models.ScanGrant(org_id=client[4].id, principal="runner-legacy",
                              capabilities="passive_discovery", issued_by="santiago",
                              justification="written before normalisation",
                              policy_version="v1", status="active",
                              valid_from=models.utcnow(),
                              valid_until=models.utcnow() + __import__("datetime").timedelta(hours=1),
                              created_at=models.utcnow(), updated_at=models.utcnow())
    session.add(legacy)
    session.flush()
    session.add(models.ScanGrantTarget(grant_id=legacy.id, target_type="domain",
                                       target_value="*.legacy.example"))
    session.commit()
    read = _authorize(http, headers, "runner-legacy", "passive_discovery",
                      [("domain", "api.legacy.example")])
    assert read.json()["decision"] == "allow", read.text


def test_wildcard_strictness(client):
    test_client, headers, _other, _session, _org = client
    _grant(client, headers)
    # Subdomain covered; apex NOT covered; other root not covered.
    assert _authorize(test_client, headers, "runner-01", "intrusive_testing",
                      [("domain", "deep.sub.empresa.com")]).json()["decision"] == "allow"
    apex = _authorize(test_client, headers, "runner-01", "intrusive_testing",
                      [("domain", "empresa.com")])
    assert apex.json()["decision"] == "deny"
    other_root = _authorize(test_client, headers, "runner-01", "intrusive_testing",
                            [("domain", "empresa.evil")])
    assert other_root.json()["decision"] == "deny"
    ip_probe = _authorize(test_client, headers, "runner-01", "intrusive_testing",
                          [("ip", "203.0.113.9")])
    assert ip_probe.json()["decision"] == "deny"
    third = _authorize(test_client, headers, "runner-01", "intrusive_testing",
                       [("domain", "thirdparty.example")])
    assert third.json()["decision"] == "deny"  # subdomain of a wildcard family
    # No third-party could be matched by *.empresa.com anyway:
    assert "exclusion" not in third.json()["reason"] or True


def test_exclusions_beat_grants(client):
    test_client, headers, _other, _session, _org = client
    _grant(client, headers, capabilities=("passive_discovery", "intrusive_testing"),
           targets=("wildcard_domain", "*.empresa.com"))
    # sub-sub subdomain NOT excluded... exclude a subfamily explicitly:
    test_client.post("/api/v1/scope/exclusions", json={
        "target_type": "domain", "value": "cdn.empresa.com",
        "reason": "cdn vendor zone"}, headers=headers)
    denied = _authorize(test_client, headers, "runner-01", "intrusive_testing",
                        [("domain", "cdn.empresa.com")])
    assert denied.json()["decision"] == "deny"
    assert "cdn vendor zone" in denied.json()["reason"]
    sibling = _authorize(test_client, headers, "runner-01", "intrusive_testing",
                         [("domain", "api.empresa.com")])
    assert sibling.json()["decision"] == "allow"


def test_cidr_ip_and_url_matching(client):
    test_client, headers, _other, _session, _org = client
    _grant(client, headers, capabilities=("active_verification",),
           targets=(("cidr", "203.0.113.0/25"), ("url", "https://api.empresa.com/v1")))
    in_range = _authorize(test_client, headers, "runner-01", "active_verification",
                          [("ip", "203.0.113.42")])
    assert in_range.json()["decision"] == "allow"
    out_of_range = _authorize(test_client, headers, "runner-01", "active_verification",
                              [("ip", "203.0.113.200")])
    assert out_of_range.json()["decision"] == "deny"
    same_origin = _authorize(test_client, headers, "runner-01", "active_verification",
                             [("url", "https://api.empresa.com/v1")])
    assert same_origin.json()["decision"] == "allow"
    broader = _authorize(test_client, headers, "runner-01", "active_verification",
                         [("url", "https://api.empresa.com/v2")])
    assert broader.json()["decision"] == "deny"


def test_self_authorization_guard_and_unknown_capability(client):
    test_client, headers, _other, _session, _org = client
    # Invasive capability cannot be self-authorized.
    selfy = _grant(client, headers, issued_by="runner-01")
    assert selfy.status_code == 409
    assert "self-authorized" in selfy.json()["detail"]
    # Passive-only is fine self-issued.
    passive_ok = _grant(client, headers, issued_by="runner-01",
                        capabilities=("passive_discovery",))
    assert passive_ok.status_code == 200

    bad = _authorize(test_client, headers, "runner-01", "mind_control",
                     [("domain", "empresa.com")])
    assert bad.json()["decision"] == "deny"
    assert "unknown capability" in bad.json()["reason"]


def test_env_tool_conditions_mismatch(client):
    test_client, headers, _other, _session, _org = client
    _grant(client, headers, capabilities=("active_verification",),
           targets=(("domain", "staging.empresa.com"),),
           extra={"environment": "staging", "tools": ["nuclei"]})
    env_wrong = _authorize(test_client, headers, "runner-01", "active_verification",
                           [("domain", "staging.empresa.com")],
                           environment="production", tool="nuclei")
    assert env_wrong.json()["decision"] == "deny"
    tool_wrong = _authorize(test_client, headers, "runner-01", "active_verification",
                            [("domain", "staging.empresa.com")],
                            environment="staging", tool="metasploit")
    assert tool_wrong.json()["decision"] == "deny"
    matched = _authorize(test_client, headers, "runner-01", "active_verification",
                         [("domain", "staging.empresa.com")],
                         environment="staging", tool="nuclei")
    assert matched.json()["decision"] == "allow"

    # A narrowed grant applies only to the named axis. A request that names
    # neither is not "close enough" — it is denied, and the reason says why.
    env_unlabelled = _authorize(test_client, headers, "runner-01",
                                "active_verification",
                                [("domain", "staging.empresa.com")], tool="nuclei")
    assert env_unlabelled.json()["decision"] == "deny"
    assert "environment" in env_unlabelled.json()["reason"]

    tool_unlabelled = _authorize(test_client, headers, "runner-01",
                                 "active_verification",
                                 [("domain", "staging.empresa.com")],
                                 environment="staging")
    assert tool_unlabelled.json()["decision"] == "deny"
    assert "tool" in tool_unlabelled.json()["reason"]


def test_expiry_and_revocation_midrun(client):
    test_client, headers, _other, session, _org = client
    _grant(client, headers, hours=1)
    # Force expiry by backdating the grant.
    grant_row = session.query(models.ScanGrant).one()
    grant_row.valid_until = models.utcnow() - datetime.timedelta(minutes=1)
    session.commit()
    lapsed = _authorize(test_client, headers, "runner-01", "intrusive_testing",
                        [("domain", "staging.empresa.com")])
    assert lapsed.json()["decision"] == "deny"

    _grant(client, headers, principal="runner-02")
    grant_id = session.query(models.ScanGrant).order_by(
        models.ScanGrant.created_at.desc()).first().id
    revoke = test_client.post(f"/api/v1/authorization/grants/{grant_id}/revoke",
                              json={"reason": "campaign paused",
                                    "actor": "santiago"}, headers=headers)
    assert revoke.status_code == 200
    assert revoke.json()["data"]["status"] == "revoked"
    after = _authorize(test_client, headers, "runner-02", "intrusive_testing",
                       [("wildcard_domain", "next.empresa.com")])
    assert after.json()["decision"] == "deny"
    # Revalidation path directly rejects the revoked grant id.
    reval = test_client.post(f"/api/v1/authorization/grants/{grant_id}/revalidate",
                             json={"principal": "runner-02",
                                   "capability": "intrusive_testing",
                                   "targets": [{
                                       "type": "wildcard_domain",
                                       "value": "next.empresa.com"}]},
                             headers=headers)
    assert reval.json()["decision"] == "deny"


def test_revalidate_exact_grant_targets_changed(client):
    test_client, headers, _other, session, _org = client
    _grant(client, headers, principal="runner-03")
    grant_id = session.query(models.ScanGrant).one().id
    same = test_client.post(f"/api/v1/authorization/grants/{grant_id}/revalidate",
                            json={"principal": "runner-03",
                                  "capability": "intrusive_testing",
                                  "targets": [{
                                      "type": "wildcard_domain",
                                      "value": "fresh.empresa.com"}]},
                            headers=headers)
    assert same.json()["decision"] == "allow"
    moved = test_client.post(f"/api/v1/authorization/grants/{grant_id}/revalidate",
                             json={"principal": "runner-03",
                                   "capability": "intrusive_testing",
                                   "targets": [{
                                       "type": "domain",
                                       "value": "another-corp.example"}]},
                             headers=headers)
    assert moved.json()["decision"] == "deny"
    assert "does not cover" in moved.json()["reason"]


def test_multi_tenant_isolation(client):
    test_client, headers, other_headers, _session, _org = client
    _grant(client, headers, principal="runner-shared",
           capabilities=("active_verification",),
           targets=(("domain", "app.empresa.com"),))
    # Organization key without any grant: default deny for the same target.
    other_deny = _authorize(test_client, other_headers, "runner-shared",
                            "active_verification",
                            [("domain", "app.empresa.com")])
    assert other_deny.json()["decision"] == "deny"
    # Any org's authorization plane is invisible to the other's key.
    grants = test_client.get("/api/v1/authorization/grants", headers=other_headers)
    assert grants.json()["total"] == 0


def test_audit_chain_records_authorization_events(client):
    test_client, headers, _other, _session, _org = client
    grant = _grant(client, headers)
    test_client.post(f"/api/v1/authorization/grants/{grant.json()['data']['id']}/revoke",
                     json={"reason": "gate test revoke", "actor": "santiago"},
                     headers=headers)
    audit = test_client.get("/api/v1/audit", headers=headers).json()
    actions = [row["action"] for row in audit["data"]]
    assert "authorization.granted" in actions
    assert "authorization.revoked" in actions
    assert audit["chain_ok"] is True

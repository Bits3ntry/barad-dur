"""Declaring an asset asks for authorization; only Grants can answer it.

The rule under test is the whole point of the flow: an asset row exists the
moment somebody declares it, and authority over it exists only when an
administrator approves the request — possibly widened to a subtree or the zone,
never by default. `scope_options` is the only place that decides what "everything
under it" means, and the apex is always included explicitly because `*.base`
never covers `base`.

Nothing here is scanned: the flow is declaration → request → approval →
permission, and permission is still checked by `authorization.authorize`.
"""
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import authorization, models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/assets.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "assets")
    session.add(models.ScopeExclusion(
        org_id=org.id, target_type="domain", value="thirdparty.example",
        reason="a supplier's box, never ours to touch"))
    session.commit()
    from fastapi.testclient import TestClient

    return TestClient(app), {"X-API-Key": key}, session, org


def _declare(client, headers, value, **extra):
    payload = {"type": "domain", "value": value, "actor": "santiago", **extra}
    return client.post("/api/v1/assets", json=payload, headers=headers)


def _requests(client, headers):
    response = client.get("/api/v1/authorization/grants?status=requested",
                          headers=headers)
    assert response.status_code == 200
    return response.json()["data"]


def _authorize(client, headers, capability, value, principal="collector"):
    payload = {"principal": principal, "capability": capability,
               "targets": [{"type": "domain", "value": value}]}
    return client.post("/api/v1/authorization/authorize", json=payload,
                       headers=headers).json()


def test_declaring_a_domain_opens_one_request_and_grants_nothing(client):
    http, headers, session, org = client
    body = _declare(http, headers, "dev.api.dominio.com").json()

    assert body["authorization"]["covered"] is False
    assert body["authorization"]["request"]["status"] == "requested"
    assert body["authorization"]["request"]["level"] == "simple"
    # The ask is exactly what was declared: one target, nothing inherited.
    assert body["authorization"]["request"]["targets"] == [
        {"type": "domain", "value": "dev.api.dominio.com"}]

    # A request is not permission: the engine only reads active grants.
    assert _authorize(http, headers, "passive_discovery",
                      "dev.api.dominio.com")["decision"] == "deny"
    assert len(_requests(http, headers)) == 1

    # Declaring it twice does not queue the same question twice.
    again = _declare(http, headers, "dev.api.dominio.com").json()
    assert again["already_known"] is True
    assert again["authorization"]["request"]["id"] == \
        body["authorization"]["request"]["id"]
    assert len(_requests(http, headers)) == 1


def test_approving_without_edits_grants_exactly_that_value(client):
    http, headers, session, org = client
    declared = _declare(http, headers, "dev.api.dominio.com").json()
    grant_id = declared["authorization"]["request"]["id"]

    approved = http.post(f"/api/v1/authorization/grants/{grant_id}/approve",
                         json={"actor": "santiago"}, headers=headers)
    assert approved.status_code == 200, approved.text
    data = approved.json()["data"]
    assert data["status"] == "active"
    assert data["level"] == "simple"
    assert data["approved_by"] == "santiago"
    assert data["targets"] == [{"type": "domain", "value": "dev.api.dominio.com"}]

    assert _authorize(http, headers, "passive_discovery",
                      "dev.api.dominio.com")["decision"] == "allow"
    assert _authorize(http, headers, "active_verification",
                      "dev.api.dominio.com")["decision"] == "allow"
    # Nothing else came with it.
    assert _authorize(http, headers, "passive_discovery",
                      "api.dominio.com")["decision"] == "deny"
    assert _authorize(http, headers, "passive_discovery",
                      "dev.api.dominio.com.evil.example")["decision"] == "deny"
    # And a simple scan is not red teaming.
    assert _authorize(http, headers, "intrusive_testing",
                      "dev.api.dominio.com")["decision"] == "deny"

    # The approval is what puts the target in scope, with its provenance.
    scope = http.get("/api/v1/scope/targets", headers=headers).json()["data"]
    assert any(row["value"] == "dev.api.dominio.com" and row["source"] == "grant"
               for row in scope), scope


def test_widening_covers_the_parent_subtree_but_never_the_zone(client):
    http, headers, session, org = client
    # The three scopes are computed by the engine, not typed by the console.
    options = http.get(
        "/api/v1/authorization/scope-options?value=dev.api.dominio.com",
        headers=headers).json()["data"]
    by_scope = {option["scope"]: option for option in options}
    assert set(by_scope) == {"exact", "subtree", "zone"}
    subtree = [t["value"] for t in by_scope["subtree"]["targets"]]
    assert subtree == ["api.dominio.com", "*.api.dominio.com"]
    zone = [t["value"] for t in by_scope["zone"]["targets"]]
    assert zone == ["dominio.com", "*.dominio.com"]

    declared = _declare(http, headers, "dev.api.dominio.com").json()
    grant_id = declared["authorization"]["request"]["id"]
    approved = http.post(
        f"/api/v1/authorization/grants/{grant_id}/approve",
        json={"actor": "santiago", "targets": by_scope["subtree"]["targets"]},
        headers=headers)
    assert approved.status_code == 200, approved.text

    # The sibling, the apex and any depth below it are covered…
    for value in ("api.dominio.com", "dev.api.dominio.com", "qa.api.dominio.com",
                  "a.b.api.dominio.com"):
        assert _authorize(http, headers, "passive_discovery", value)[
            "decision"] == "allow", value
    # …and the rest of the zone is not: widening one step is not widening all.
    for value in ("dominio.com", "dev.otro.dominio.com", "otro.dominio.com"):
        assert _authorize(http, headers, "passive_discovery", value)[
            "decision"] == "deny", value


def test_a_covered_domain_declares_without_asking(client):
    http, headers, session, org = client
    issued = http.post("/api/v1/authorization/grants", json={
        "principal": "collector", "level": "simple",
        "targets": [{"type": "wildcard_domain", "value": "*.dominio.com"}],
        "issued_by": "santiago", "justification": "production estate",
        "hours": 24,
    }, headers=headers)
    assert issued.status_code == 200, issued.text

    body = _declare(http, headers, "prod.dominio.com").json()
    assert body["authorization"]["covered"] is True
    assert body["authorization"]["request"] is None
    assert _requests(http, headers) == []


def test_an_excluded_domain_asks_nobody_for_anything(client):
    http, headers, session, org = client
    body = _declare(http, headers, "thirdparty.example").json()
    assert body["authorization"]["covered"] is False
    assert body["authorization"]["excluded"] is True
    assert body["authorization"]["request"] is None
    assert _requests(http, headers) == []


def test_a_rejected_request_stays_inert_and_says_why(client):
    http, headers, session, org = client
    declared = _declare(http, headers, "blog.dominio.com").json()
    grant_id = declared["authorization"]["request"]["id"]
    rejected = http.post(f"/api/v1/authorization/grants/{grant_id}/reject",
                         json={"actor": "santiago",
                               "reason": "not ours; the agency hosts it"},
                         headers=headers)
    assert rejected.status_code == 200, rejected.text
    assert rejected.json()["data"]["status"] == "rejected"
    assert "agency" in rejected.json()["data"]["rejection_reason"]
    assert _authorize(http, headers, "passive_discovery",
                      "blog.dominio.com")["decision"] == "deny"


def test_scan_levels_are_bundles_of_capabilities():
    assert authorization.capabilities_for_level("simple") == [
        "passive_discovery", "active_verification"]
    assert "intrusive_testing" not in authorization.capabilities_for_level("advanced")
    assert "intrusive_testing" in authorization.capabilities_for_level("redteam")
    assert authorization.level_for_capabilities(
        ["passive_discovery", "active_verification"]) == "simple"
    assert authorization.level_for_capabilities(
        ["passive_discovery", "active_verification", "vulnerability_analysis"]
    ) == "advanced"
    with pytest.raises(ValueError):
        authorization.capabilities_for_level("everything")


def test_scope_options_keep_country_zones_whole():
    # `api.bitsentry.com.ar`: its parent IS the zone, so the two options collapse.
    collapsed = {option["scope"] for option in
                 authorization.scope_options(["api.bitsentry.com.ar"])}
    assert collapsed == {"exact", "subtree"}

    options = authorization.scope_options(["api.dev.bitsentry.com.ar"])
    scopes = {option["scope"]: option for option in options}
    assert [t["value"] for t in scopes["zone"]["targets"]] == [
        "bitsentry.com.ar", "*.bitsentry.com.ar"]
    assert [t["value"] for t in scopes["subtree"]["targets"]] == [
        "dev.bitsentry.com.ar", "*.dev.bitsentry.com.ar"]


def test_a_set_of_subdomains_widens_to_its_common_ancestor():
    options = authorization.scope_options(
        ["a.api.dominio.com", "b.api.dominio.com"])
    scopes = {option["scope"]: option for option in options}
    assert [t["value"] for t in scopes["subtree"]["targets"]] == [
        "api.dominio.com", "*.api.dominio.com"]
    assert [t["value"] for t in scopes["zone"]["targets"]] == [
        "dominio.com", "*.dominio.com"]

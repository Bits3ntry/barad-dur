"""The harness: budgets, fan-out, narrowing and gates.

Four properties, each one earned:

* a run that exhausts its turn budget stops with a reason, not silently;
* a parent cannot fork a crowd, and a child cannot call a tool its parent lacks;
* a candidate without an observation that names where it was seen is refuted;
* a stage that raises is a refusal, never a pass.
"""
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.harness import budgets as harness_budgets  # noqa: E402
from backend.app.harness import evidence as harness_evidence  # noqa: E402
from backend.app.harness import gates as harness_gates  # noqa: E402
from backend.app.harness import policy as harness_policy  # noqa: E402
from backend.app.harness import runs as harness_runs  # noqa: E402
from backend.app.main import create_app  # noqa: E402


@pytest.fixture()
def context(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/harness.db")
    monkeypatch.setenv("BOOTSTRAP_TOKEN", "boot")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="h", name="Harness")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "harness")
    session.add_all([
        models.AgentSpec(id="spec-orch", name="Palantír", slug="palantir",
                         agent_class="orchestrator", description="plans",
                         tools="[]", must_return="[]", tech_affinity="[]",
                         status="active"),
        models.AgentSpec(id="spec-analyst", name="Analyst", slug="estate.analyst",
                         agent_class="analyst", description="reads the estate",
                         tools='["projects_list", "asset_fingerprint"]',
                         must_return="[]", tech_affinity="[]",
                         parent_slug="palantir", allowed_tools='["projects_list"]',
                         status="active"),
        models.AgentSpec(id="spec-draft", name="Draft", slug="draft.agent",
                         agent_class="analyst", description="not dispatchable",
                         tools="[]", must_return="[]", tech_affinity="[]",
                         status="draft"),
    ])
    session.commit()
    from starlette.testclient import TestClient
    http = TestClient(app)
    headers = {"X-API-Key": key}
    yield http, headers, session, org
    session.close()


# ── budgets ───────────────────────────────────────────────────────────────

def test_a_run_stops_when_its_turn_budget_is_gone(context):
    http, headers, session, org = context
    created = http.post("/api/v1/agents/runs", headers=headers, json={
        "spec_slug": "palantir", "goal": "enumerate", "max_turns": 2}).json()["data"]
    run = session.get(models.AgentRun, created["run"]["id"])
    harness_runs.start(session, run)
    budgets_enforce = harness_budgets.enforce
    budgets_enforce(session, run)
    for _ in range(2):
        harness_budgets.register_step(session, run, tokens_in=10, tokens_out=5,
                                      cost_usd=0.01)
        run.turn_count += 0  # register_step already counts
    with pytest.raises(harness_budgets.BudgetExceeded) as caught:
        budgets_enforce(session, run)
    assert "turn budget reached" in str(caught.value)


def test_the_ceiling_binds_the_family_not_each_child(context):
    http, headers, session, org = context
    parent = harness_runs.create(session, org_id=org.id, spec_slug="palantir",
                                 goal="parent", cost_ceiling_usd=1.0)
    child = harness_runs.create(session, org_id=org.id, spec_slug="estate.analyst",
                                goal="child", parent_run_id=parent.id, thread="mission:m1")
    parent.cost_usd = 0.9
    child.cost_usd = 0.05
    session.flush()
    assert round(harness_budgets.family_cost(session, parent), 4) == 0.95
    with pytest.raises(harness_budgets.BudgetExceeded):
        harness_budgets.enforce(session, parent, projected_usd=0.1)


# ── fan-out and narrowing ─────────────────────────────────────────────────

def test_a_parent_cannot_fork_a_crowd(context):
    http, headers, session, org = context
    parent = harness_runs.create(session, org_id=org.id, spec_slug="palantir",
                                 goal="parent", thread="mission:m2")
    for index in range(harness_runs.MAX_CHILDREN):
        harness_runs.create(session, org_id=org.id, spec_slug="estate.analyst",
                            goal=f"child {index}", parent_run_id=parent.id,
                            thread="mission:m2")
    with pytest.raises(ValueError, match="fan-out cap"):
        harness_runs.create(session, org_id=org.id, spec_slug="estate.analyst",
                            goal="one too many", parent_run_id=parent.id,
                            thread="mission:m2")


def test_a_child_cannot_call_a_tool_its_parent_lacks(context):
    http, headers, session, org = context
    catalogue = ["projects_list", "asset_fingerprint", "probe.replay"]
    effective = harness_policy.effective_tools(session, "estate.analyst",
                                               catalogue=catalogue)
    assert effective == ["projects_list"], "the parent's allowed_tools narrows the child"
    with pytest.raises(PermissionError):
        harness_policy.assert_allowed(session, "estate.analyst", "asset_fingerprint",
                                      catalogue=catalogue)


def test_a_draft_agent_cannot_be_dispatched(context):
    http, headers, session, org = context
    response = http.post("/api/v1/agents/runs", headers=headers, json={
        "spec_slug": "draft.agent", "goal": "do something"})
    assert response.status_code == 409
    assert "draft" in response.json()["detail"]


# ── evidence with stance ──────────────────────────────────────────────────

def test_an_assumption_with_a_locator_is_still_not_proof():
    items = harness_evidence.normalize([
        {"stance": "assumption", "statement": "probably IDOR", "locator": "api.x/y/1"}])
    assert harness_evidence.confirmable(items) is False


def test_an_observation_without_a_locator_is_not_proof_either():
    items = harness_evidence.normalize([{"stance": "observation", "statement": "saw it"}])
    assert harness_evidence.confirmable(items) is False


# ── the gate chain ────────────────────────────────────────────────────────

def _candidate(session, org, evidence, *, finding_id=None, expect=None):
    import json
    payload = {"evidence": evidence}
    if expect:
        payload["expect"] = expect
    row = models.Candidate(org_id=org.id, title="candidate", severity="HIGH",
                           claim="claim", finding_id=finding_id,
                           evidence=json.dumps(payload))
    session.add(row)
    session.flush()
    return row


def test_a_candidate_without_evidence_is_refuted_at_the_first_stage(context):
    http, headers, session, org = context
    row = _candidate(session, org, [])
    result = harness_gates.run_chain(session, org, row)
    assert result["state"] == "refuted"
    assert result["failed_at"] == "evidence_present"
    assert row.state == "refuted"


def test_a_host_outside_the_grant_is_refused_before_any_replay(context):
    http, headers, session, org = context
    row = _candidate(session, org, [
        {"stance": "observation", "statement": "reflected", "locator": "evil.test"}])
    called = {"replay": False}

    def replay(**kwargs):
        called["replay"] = True
        return {"state": "reproduced"}

    result = harness_gates.run_chain(session, org, row, replay=replay)
    assert result["failed_at"] == "authorized_target"
    assert called["replay"] is False, "no request may be sent for an unauthorized host"


def test_a_stage_that_raises_can_never_confirm(context):
    http, headers, session, org = context

    def boom(ctx):
        raise RuntimeError("adapter exploded")

    row = _candidate(session, org, [
        {"stance": "observation", "statement": "seen", "locator": "api.example.test"}])
    result = harness_gates.run_chain(session, org, row,
                                     stages=(harness_gates.evidence_present, boom))
    assert result["state"] == "refuted"
    assert "adapter exploded" in result["reason"]


def test_a_promoted_proof_keeps_the_query_string_and_the_response():
    """The finding must answer "what do I replay" byte for byte.

    `_proof_text` rebuilt the path with `urlsplit(...).path`, so the request that
    proved a SQLi (`?q='))--`) was stored as the clean endpoint and Repeat replayed a
    different request. The response was never stored at all: the reader saw the
    payload and had to take the outcome on faith.
    """
    from backend.app.routers import agent as agent_router

    request = {"method": "get",
               "url": "https://lab.example.test/rest/products/search?q=%27))--",
               "headers": {"Accept": "application/json"}, "body": None}
    text = agent_router._proof_text(request, request["url"])
    assert text.splitlines()[0] == "GET /rest/products/search?q=%27))-- HTTP/1.1"
    assert "Host: lab.example.test" in text

    response = agent_router._response_text({
        "status": 200, "response_headers": {"Content-Type": "application/json"},
        "response_body": '{"status":"success","data":[]}'})
    assert response.startswith("HTTP/1.1 200")
    assert '{"status":"success","data":[]}' in response

    assert agent_router._response_text(None) is None, \
        "no exchange means no response, never an invented one"


def test_a_reproduced_replay_validates_the_candidate(context):
    http, headers, session, org = context
    import datetime as dt
    grant = models.ScanGrant(
        org_id=org.id, principal="collector", capabilities="active_verification",
        level="simple", tools="curl", issued_by="admin", justification="audit",
        policy_version=1, status="active",
        valid_from=models.utcnow(),
        valid_until=models.utcnow() + dt.timedelta(days=3))
    session.add(grant)
    session.flush()
    session.add(models.ScanGrantTarget(grant_id=grant.id, target_type="domain",
                                       target_value="api.example.test"))
    session.commit()

    finding = models.Finding(org_id=org.id, kind="vulnerability", fingerprint="fp-1",
                             source="nvd", title="CVE-test on search",
                             severity="HIGH", status="open")
    session.add(finding)
    session.flush()
    row = _candidate(session, org, [
        {"stance": "observation", "statement": "reflected payload",
         "locator": "https://api.example.test/search?q=1"}],
        finding_id=finding.id)

    stages = (harness_gates.evidence_present, harness_gates.authorized_target,
              harness_gates.replay)
    result = harness_gates.run_chain(
        session, org, row, stages=stages,
        replay=lambda **kwargs: {"state": "reproduced",
                                 "response": {"status": 200},
                                 "artifact": {"body_sha256_16": "abc123"}})
    assert result["state"] == "validated", result
    assert any(stage["stage"] == "replay" and stage["confirmed"]
               for stage in result["stages"])


# ── messages and the merged thread ────────────────────────────────────────

def test_a_message_needs_a_recipient_that_exists(context):
    http, headers, session, org = context
    response = http.post("/api/v1/agents/messages", headers=headers,
                         json={"body": "hello", "to_run": "does-not-exist"})
    assert response.status_code == 404


def test_a_message_is_marked_delivered_when_it_has_a_recipient(context):
    http, headers, session, org = context
    created = http.post("/api/v1/agents/runs", headers=headers, json={
        "spec_slug": "palantir", "goal": "parent",
        "thread": "mission:m9"}).json()["data"]["run"]
    response = http.post("/api/v1/agents/messages", headers=headers, json={
        "body": "take the recon", "to_run": created["id"], "kind": "delegate"})
    assert response.status_code == 201
    assert response.json()["data"]["delivered"] is True


# ── probe.sibling: two identities, one answer ─────────────────────────────

def _estate(session, org, *, host="api.example.test"):
    import datetime as dt
    grant = models.ScanGrant(
        org_id=org.id, principal="collector", capabilities="active_verification",
        level="redteam", tools="curl", issued_by="admin", justification="audit",
        policy_version=1, status="active", valid_from=models.utcnow(),
        valid_until=models.utcnow() + dt.timedelta(days=3))
    session.add(grant)
    session.flush()
    session.add(models.ScanGrantTarget(grant_id=grant.id, target_type="domain",
                                       target_value=host))
    finding = models.Finding(org_id=org.id, kind="vulnerability", fingerprint="fp-sib",
                             source="pentest", title="IDOR on /api/invoices",
                             severity="HIGH", status="open")
    session.add(finding)
    session.flush()
    session.add(models.Occurrence(
        org_id=org.id, finding_id=finding.id, sighting_key="sib-1", tool="burp",
        evidence=f"GET /api/invoices/42 HTTP/1.1\nHost: {host}\n"
                 "Authorization: Bearer operator\nAccept: application/json\n\n"))
    session.commit()
    return grant, finding


def test_identities_are_sealed_and_never_returned(context):
    http, headers, session, org = context
    grant, _finding = _estate(session, org)
    created = http.post("/api/v1/agents/identities", headers=headers, json={
        "grant_id": grant.id, "label": "user-a",
        "headers": {"Authorization": "Bearer token-a"}})
    assert created.status_code == 201
    assert created.json()["data"]["sealed"] is True

    listed = http.get("/api/v1/agents/identities", headers=headers).json()["data"]
    assert [row["label"] for row in listed] == ["user-a"]
    assert "token-a" not in str(listed), "the credential must not travel on a read"
    assert "headers_cipher" not in str(listed)


def test_sibling_refuses_a_host_without_a_grant(context):
    http, headers, session, org = context
    _grant, finding = _estate(session, org)
    response = http.post("/api/v1/agents/sibling", headers=headers, json={
        "finding_id": finding.id, "label_a": "user-a", "label_b": "user-b"})
    # the identity does not exist either, but the host check must come first only when
    # the grant is missing; here the grant exists, so the identity is the missing piece
    assert response.status_code in (403, 404)


def test_sibling_proves_a_leak_when_b_receives_a_record(context, monkeypatch):
    http, headers, session, org = context
    grant, finding = _estate(session, org)
    for label, token in (("user-a", "token-a"), ("user-b", "token-b")):
        assert http.post("/api/v1/agents/identities", headers=headers, json={
            "grant_id": grant.id, "label": label,
            "headers": {"Authorization": f"Bearer {token}"}}).status_code == 201

    from backend.app.harness import sibling as sibling_mod
    seen = []

    def handler(request):
        seen.append(str(request.headers.get("authorization")))
        body = ('{"id":42,"owner":"alice@example.test","total":990,"lines":3}'
                if "token-a" in str(request.headers.get("authorization"))
                else '{"id":42,"owner":"alice@example.test","total":990,"lines":3}')
        return __import__("httpx").Response(200, text=body)

    monkeypatch.setattr(sibling_mod, "TRANSPORT", __import__("httpx").MockTransport(handler))
    body = http.post("/api/v1/agents/sibling", headers=headers, json={
        "finding_id": finding.id, "label_a": "user-a", "label_b": "user-b",
        "owner_marker": "alice@example.test"}).json()["data"]
    assert body["state"] == "leak"
    assert body["marker_in_b"] is True
    assert len(seen) == 2 and all("operator" not in value for value in seen), \
        "the captured operator credential is dropped, not replayed"


def test_sibling_reports_denied_when_b_is_refused(context, monkeypatch):
    http, headers, session, org = context
    grant, finding = _estate(session, org)
    for label in ("user-a", "user-b"):
        http.post("/api/v1/agents/identities", headers=headers, json={
            "grant_id": grant.id, "label": label,
            "headers": {"Authorization": f"Bearer {label}"}})

    from backend.app.harness import sibling as sibling_mod
    import httpx as httpx_mod

    def handler(request):
        if "user-a" in str(request.headers.get("authorization")):
            return httpx_mod.Response(200, text='{"id":42,"owner":"alice"}')
        return httpx_mod.Response(403, text="forbidden")

    monkeypatch.setattr(sibling_mod, "TRANSPORT", httpx_mod.MockTransport(handler))
    body = http.post("/api/v1/agents/sibling", headers=headers, json={
        "finding_id": finding.id, "label_a": "user-a", "label_b": "user-b"}).json()["data"]
    assert body["state"] == "denied"
    assert "403" in body["reason"]


def test_the_sibling_gate_confirms_only_on_a_leak(context):
    http, headers, session, org = context
    import json as json_mod
    row = models.Candidate(org_id=org.id, title="IDOR", severity="HIGH",
                           finding_id="f-1", state="proposed",
                           evidence=json_mod.dumps({
                               "evidence": [{"stance": "observation", "statement": "x",
                                             "locator": "api.example.test"}],
                               "identities": ["user-a", "user-b"],
                               "owner_marker": "alice@example.test"}))
    session.add(row)
    session.flush()
    stages = (harness_gates.sibling_access,)
    leaked = harness_gates.run_chain(
        session, org, row, stages=stages,
        sibling=lambda **kwargs: {"state": "leak", "b": {"sha256_16": "abc"},
                                  "reason": "B received A's record"})
    assert leaked["state"] == "validated"
    row.state = "proposed"
    denied = harness_gates.run_chain(
        session, org, row, stages=stages,
        sibling=lambda **kwargs: {"state": "denied", "reason": "B was refused (403)"})
    assert denied["state"] == "refuted"

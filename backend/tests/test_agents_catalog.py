"""The agent catalogue and the thread it renders.

Two properties worth a test each:

* **A spec declares tools and never invents them.** A spec may name a tool that does
  not exist yet (`validate.finding` shipped that way), and the API answers
  `tools_missing` instead of letting the console offer a button that cannot work.
* **The thread is a projection.** Turns, the model steps behind them and catalogue
  events are merged by time, so opening "the Palantír thread" filters what happened —
  it does not create a second conversation with its own state.
"""
import json
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

import httpx

from backend.app import models
from backend.app.routers import agents  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/agents.db")
    monkeypatch.setenv("BOOTSTRAP_TOKEN", "boot")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "agents")

    session.add_all([
        models.AgentSpec(id="spec-palantir", name="Palantír", slug="palantir",
                         agent_class="orchestrator", avatar="🔮",
                         description="plans and cites", status="active",
                         tools="[]", must_return='["answer"]'),
        models.AgentSpec(id="spec-validator", name="Validator",
                         slug="validate.finding", agent_class="field",
                         avatar="🎯", description="replays a stored request",
                         status="active", tools='["crawl.site", "asset_fingerprint", "probe.replay"]',
                         must_return='["state", "artifact"]'),
    ])

    chat = models.ChatSession(id="chat-1", org_id=org.id, created_by="owner",
                              title="¿qué es node2shell?", profile_key="palantir")
    session.add(chat)
    run = models.AiRun(id="run-1", org_id=org.id, actor="owner",
                       actor_role="owner", question="q", mode="ask",
                       status="answered", model="m")
    session.add(run)
    session.add_all([
        models.ChatTurn(id="turn-1", org_id=org.id, session_id="chat-1", seq=1,
                        role="user", author="owner", content="¿qué es node2shell?",
                        citations="[]", tokens=0),
        models.AiStep(id="step-1", org_id=org.id, run_id="run-1", seq=1,
                      role="estate.inventory", tokens_in=10, tokens_out=5,
                      tool_calls=json.dumps([{"tool": "advisory_resolve",
                                              "args": {"q": "node2shell"},
                                              "status": 200}])),
        models.ChatTurn(id="turn-2", org_id=org.id, session_id="chat-1", seq=2,
                        role="orchestrator", author="owner", profile_key="palantir",
                        content="Es CVE-2026-111497.", citations="[]", tokens=15,
                        run_id="run-1"),
    ])
    session.commit()

    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}, session


def test_the_catalogue_puts_the_orchestrator_first(client):
    http, headers, _ = client
    body = http.get("/api/v1/agents", headers=headers).json()
    assert [row["slug"] for row in body["data"]] == ["palantir", "validate.finding"]
    assert body["data"][0]["avatar"] == "🔮"


def test_autocomplete_filters_by_name_and_slug(client):
    http, headers, _ = client
    body = http.get("/api/v1/agents?q=val", headers=headers).json()
    assert [row["slug"] for row in body["data"]] == ["validate.finding"]


def test_a_spec_that_names_a_missing_tool_says_so(client):
    http, headers, _ = client
    body = http.get("/api/v1/agents?q=validator", headers=headers).json()
    row = body["data"][0]
    assert row["tools"] == ["crawl.site", "asset_fingerprint", "probe.replay"]
    assert row["tools_missing"] == ["crawl.site"], "declared is not the same as real"


def test_creating_and_patching_an_agent(client):
    http, headers, _ = client
    created = http.post("/api/v1/agents", json={
        "name": "Change impact", "slug": "change.impact", "agent_class": "analyst",
        "description": "what an upgrade breaks", "avatar": "🔁",
        "tools": ["components_impact"], "status": "draft"}, headers=headers)
    assert created.status_code == 201, created.text
    agent_id = created.json()["data"]["id"]

    duplicated = http.post("/api/v1/agents", json={
        "name": "Other", "slug": "change.impact"}, headers=headers)
    assert duplicated.status_code == 409

    patched = http.patch(f"/api/v1/agents/{agent_id}",
                         json={"status": "active", "tools": ["components_impact",
                                                            "no.such.tool"]},
                         headers=headers).json()["data"]
    assert patched["status"] == "active"
    assert patched["tools_missing"] == ["no.such.tool"]

    bad = http.post("/api/v1/agents", json={"name": "X", "slug": "x",
                                            "agent_class": "wizard"}, headers=headers)
    assert bad.status_code == 422


def test_the_tool_catalogue_names_who_uses_each_tool(client):
    http, headers, _ = client
    body = http.get("/api/v1/agents/tools", headers=headers).json()
    by_name = {row["name"]: row for row in body["data"]}
    assert "findings_search" in by_name
    assert by_name["findings_search"]["path"].startswith("/api/v1/")


def test_the_thread_merges_turns_steps_and_events_in_order(client):
    http, headers, session = client
    org = session.query(models.Organization).one()
    appended = http.post("/api/v1/agents/threads/chat:chat-1/events", json={
        "body": "aprobar el plan", "kind": "decision",
        "refs": ["CVE-2026-111497"]}, headers=headers)
    assert appended.status_code == 201

    body = http.get("/api/v1/agents/threads/chat:chat-1/events",
                    headers=headers).json()
    kinds = [event["kind"] for event in body["data"]]
    assert kinds.count("message") == 2
    assert "step" in kinds and "decision" in kinds
    # The orchestrator's line carries its avatar; the step carries the tool it ran.
    palantir = [e for e in body["data"] if e.get("author") == "palantir"][0]
    assert palantir["avatar"] == "🔮"
    step = [e for e in body["data"] if e["kind"] == "step"][0]
    assert step["tools"][0]["tool"] == "advisory_resolve"


def test_opening_the_palantir_thread_is_a_filter_not_a_second_conversation(client):
    http, headers, _ = client
    only = http.get("/api/v1/agents/threads/chat:chat-1/events?author=palantir",
                    headers=headers).json()
    assert [event["kind"] for event in only["data"]] == ["message"]
    assert only["data"][0]["body"].startswith("Es CVE")

    threads = http.get("/api/v1/agents/threads", headers=headers).json()
    assert threads["data"][0]["thread"] == "chat:chat-1"
    assert threads["data"][0]["turns"] == 2


def test_a_thread_that_does_not_exist_is_a_404(client):
    http, headers, _ = client
    assert http.get("/api/v1/agents/threads/chat:nope/events",
                    headers=headers).status_code == 404
    assert http.get("/api/v1/agents/threads/nonsense/events",
                    headers=headers).status_code == 422


# ── the entry: authorized domains and the read half of a probe ───────────────

@pytest.fixture()
def estate(client):
    """One classified host, one active grant, one runtime component behind it."""
    import datetime as dt

    http, headers, session = client
    org = session.query(models.Organization).one()
    project = models.Project(org_id=org.id, name="AUREA", slug="aurea")
    session.add(project)
    session.flush()
    version = models.ProjectVersion(project_id=project.id, version="main")
    session.add(version)
    session.flush()
    component = models.Component(org_id=org.id, identity_key="pkg:docker/node@22-alpine",
                                 purl="pkg:docker/node@22-alpine", name="node",
                                 version="22-alpine")
    other = models.Component(org_id=org.id, identity_key="pkg:npm/react@19.1.0",
                             purl="pkg:npm/react@19.1.0", name="react", version="19.1.0")
    session.add_all([component, other])
    session.flush()
    session.add_all([
        models.VersionComponent(project_version_id=version.id,
                                component_id=component.id, is_direct=True),
        models.VersionComponent(project_version_id=version.id,
                                component_id=other.id, is_direct=True),
    ])
    asset = models.Asset(org_id=org.id, type="domain", value="api.example.test",
                         source="manual", classification_status="classified",
                         project_id=project.id)
    session.add(asset)
    session.flush()
    session.add(models.Observation(org_id=org.id, asset_id=asset.id, kind="technology",
                                   subject="https://api.example.test",
                                   value={"label": "nginx", "version": "1.25"}))
    session.add(models.Finding(org_id=org.id, kind="vulnerability", fingerprint="fp-9",
                               source="nvd", title="CVE-2026-111497 on node",
                               severity="CRITICAL", status="open", asset_id=asset.id,
                               component_id=component.id))
    # A dependency CVE lives on the component: the host answers "0" unless the
    # fingerprint also reads its project's findings.
    session.add(models.Finding(org_id=org.id, kind="vulnerability", fingerprint="fp-10",
                               source="nvd", title="CVE-2026-48710 on starlette",
                               severity="HIGH", status="open",
                               project_id=project.id, component_id=other.id))
    grant = models.ScanGrant(
        org_id=org.id, principal="collector", capabilities="active_verification",
        level="simple", tools="curl", issued_by="admin", justification="audit",
        policy_version=1, status="active", asset_id=asset.id,
        valid_from=models.utcnow(),
        valid_until=models.utcnow() + dt.timedelta(days=7))
    session.add(grant)
    session.flush()
    session.add(models.ScanGrantTarget(grant_id=grant.id, target_type="domain",
                                       target_value="api.example.test"))
    session.commit()
    return http, headers, session, asset, grant


def test_authorized_targets_lists_the_grant_behind_each_host(estate):
    http, headers, _session, asset, grant = estate
    body = http.get("/api/v1/agents/targets", headers=headers).json()
    row = body["data"][0]
    assert row["asset"] == "api.example.test"
    assert row["level"] == "simple"
    assert row["expired"] is False
    assert row["findings_open"] == 1
    assert row["targets"] == [{"type": "domain", "value": "api.example.test"}]


def test_fingerprint_answers_what_runs_behind_a_host_without_calling_it(estate):
    http, headers, _session, asset, grant = estate
    body = http.get("/api/v1/agents/fingerprint?asset=api.example.test",
                    headers=headers).json()["data"]
    assert body["asset"]["value"] == "api.example.test"
    assert body["runtime"] == [{"purl": "pkg:docker/node@22-alpine", "name": "node",
                                "version": "22-alpine"}], "runtime only, not every dep"
    assert body["observations"][0]["kind"] == "technology"
    titles = {(row["title"], row["scope"]) for row in body["findings"]}
    assert ("CVE-2026-111497 on node", "asset") in titles
    assert ("CVE-2026-48710 on starlette", "project") in titles


def test_the_entry_tools_are_declared_as_read_and_target_bound(estate):
    http, headers, _session, asset, grant = estate
    body = http.get("/api/v1/agents/tools", headers=headers).json()["data"]
    by_name = {row["name"]: row for row in body}
    for name in ("asset_fingerprint", "authorized_targets"):
        assert by_name[name]["risk"] == "read"
    assert by_name["asset_fingerprint"]["target_kind"] == "asset"
    assert by_name["authorized_targets"]["target_kind"] == "none"


def test_the_validator_carries_the_replay_that_makes_it_a_validator(estate):
    """Reading a host is not validating it: the tool that re-sends the request is the
    difference, and it is declared `probe` because it leaves the platform."""
    http, headers, _session, asset, grant = estate
    row = next(row for row in http.get("/api/v1/agents", headers=headers).json()["data"]
               if row["slug"] == "validate.finding")
    assert "probe.replay" in row["tools"]
    tool = next(item for item in http.get("/api/v1/agents/tools",
                                          headers=headers).json()["data"]
                if item["name"] == "probe.replay")
    assert tool["risk"] == "probe"
    assert tool["target_kind"] == "asset"


# ── probe.replay: the stored request, re-sent under a grant ──────────────────

def _with_evidence(context):
    http, headers, session, asset, grant = context
    finding = session.query(models.Finding).filter_by(fingerprint="fp-9").one()
    session.add(models.Occurrence(
        org_id=finding.org_id, finding_id=finding.id, sighting_key="s-1",
        tool="burp", source="pentest",
        evidence=("GET /api/search?q=1 HTTP/1.1\n"
                  "Host: api.example.test\n"
                  "Authorization: Bearer operator-token\n"
                  "Accept: application/json\n\n")))
    session.commit()
    return http, headers, finding


def test_replay_refuses_a_host_no_grant_covers(estate, monkeypatch):
    http, headers, _session, _asset, _grant = estate
    monkeypatch.setattr(models.Finding, "evidence_id", None, raising=False)
    monkeypatch.setattr(agents, "_TRANSPORT", httpx.MockTransport(
        lambda request: pytest.fail("nothing may be sent without a grant")))
    finding = _session.query(models.Finding).filter_by(fingerprint="fp-10").one()
    _session.add(models.Occurrence(org_id=finding.org_id, finding_id=finding.id,
                                   sighting_key="s-2",
                                   evidence="GET / HTTP/1.1\nHost: evil.test\n\n"))
    _session.commit()

    response = http.get(f"/api/v1/agents/replay?finding_id={finding.id}", headers=headers)
    assert response.status_code == 403
    assert "not covered by an active grant" in response.json()["detail"]


def test_replay_without_a_stored_request_is_blocked_not_improvised(estate, monkeypatch):
    http, headers, session, _asset, _grant = estate
    monkeypatch.setattr(agents, "_TRANSPORT", httpx.MockTransport(
        lambda request: pytest.fail("a finding without evidence must not be sent")))
    finding = session.query(models.Finding).filter_by(fingerprint="fp-10").one()

    body = http.get(f"/api/v1/agents/replay?finding_id={finding.id}",
                    headers=headers).json()["data"]
    assert body["state"] == "blocked"
    assert body["missing"] == ["stored request"]


def test_replay_sends_the_stored_request_without_replaying_credentials(estate, monkeypatch):
    http, headers, finding = _with_evidence(estate)
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["headers"] = dict(request.headers)
        return httpx.Response(200, text='{"error":"syntax error at or near SELECT"}',
                              headers={"content-type": "application/json"})

    monkeypatch.setattr(agents, "_TRANSPORT", httpx.MockTransport(handler))

    body = http.get(f"/api/v1/agents/replay?finding_id={finding.id}&expect=syntax error",
                    headers=headers).json()["data"]
    assert body["state"] == "reproduced"
    assert body["response"]["status"] == 200
    assert seen["url"] == "http://api.example.test/api/search?q=1"
    assert "authorization" not in {name.lower() for name in seen["headers"]}, \
        "a captured credential is dropped, not replayed"
    assert body["request"]["dropped_headers"] == ["Authorization"]
    assert body["artifact"]["grant_id"]


def test_the_replay_leaves_an_artefact_row_on_the_findings_thread(estate, monkeypatch):
    http, headers, finding = _with_evidence(estate)
    monkeypatch.setattr(agents, "_TRANSPORT", httpx.MockTransport(
        lambda request: httpx.Response(500, text="boom")))

    body = http.get(f"/api/v1/agents/replay?finding_id={finding.id}",
                    headers=headers).json()["data"]
    assert body["state"] == "observed", "a response is not proof the weakness survived"

    events = http.get(f"/api/v1/agents/threads/finding:{finding.id}/events",
                      headers=headers).json()["data"]
    artefacts = [row for row in events if row["kind"] == "artifact"]
    assert artefacts and finding.id in artefacts[0]["body"]


def test_a_probed_finding_appears_as_a_thread_of_its_own(estate, monkeypatch):
    """The replay writes an artefact, and the finding becomes an openable thread."""
    http, headers, finding = _with_evidence(estate)
    monkeypatch.setattr(agents, "_TRANSPORT", httpx.MockTransport(
        lambda request: httpx.Response(200, text="ok")))

    before = http.get("/api/v1/agents/threads", headers=headers).json()["data"]
    assert not [row for row in before if row["kind"] == "finding"], \
        "unprobed findings are not threads"

    http.get(f"/api/v1/agents/replay?finding_id={finding.id}", headers=headers)

    after = http.get("/api/v1/agents/threads", headers=headers).json()["data"]
    thread = next(row for row in after if row["kind"] == "finding")
    assert thread["thread"] == f"finding:{finding.id}"
    assert thread["turns"] == 1

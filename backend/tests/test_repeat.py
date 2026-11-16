"""Repeat: the chain that takes a finding from "needs a session" to "reproduced".

Three claims this file defends:

* **A login step is what makes the finding reachable.** The token extracted from
  step 1 must arrive in step 2's header; a chain that sends `{{token}}` literally
  is a 401 nobody can explain, so an unresolved placeholder stops the run.
* **Every step is authorized.** A chain is a scan typed by hand: no
  `active_verification` grant → nothing is sent, the run says `denied`, and
  mutating methods additionally need `intrusive_testing`.
* **The stored request is the one that was written.** Injected values stay as
  `{{token}}` in the record and the resolved value is reported by length only —
  the response body keeps what came back, because that is the proof.
"""
import datetime
import json
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import authorization, models, repeat  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


class FakeWire:
    """Answers by URL: the login hands out a token, the API needs it."""

    def __init__(self):
        self.sent = []

    def __call__(self, request, timeout=None):
        url = request.full_url
        method = request.get_method()
        headers = dict(request.header_items())
        self.sent.append({"method": method, "url": url, "headers": headers,
                          "body": request.data.decode() if request.data else None})

        class Response:
            def __init__(self, status, body, headers=None):
                self.status = status
                self.headers = headers or {"Content-Type": "application/json"}
                self._body = body.encode()

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, limit=None):
                return self._body

        if url.endswith("/rest/user/login"):
            return Response(200, json.dumps({"authentication": {
                "token": "jwt-from-login", "umail": "admin@juice-sh.op"}}))
        if url.endswith("/api/Users/1"):
            if headers.get("Authorization", "").endswith("jwt-from-login"):
                return Response(200, json.dumps({"data": {"id": 1, "role": "admin"}}))
            return Response(401, json.dumps({"error": "unauthorized"}))
        return Response(404, "{}")


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/repeat.db")
    monkeypatch.setenv("BOOTSTRAP_TOKEN", "boot")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "repeat")
    session.commit()
    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}, session, org


def _grant(session, org, targets, capabilities=("active_verification",)):
    """An active grant held by the platform, like the ones a console issues."""
    grant = authorization.issue_grant(
        session, org.id, principal="collector", capabilities=list(capabilities),
        targets=targets, issued_by="admin", justification="repeat tests",
        valid_until=models.utcnow() + datetime.timedelta(hours=24))
    session.commit()
    return grant


def _finding(session, org):
    row = models.Finding(
        org_id=org.id, kind="vulnerability", fingerprint="fp-repeat",
        source="pentest", title="SQL injection en el login", severity="critical",
        status="open", triage_status="new", evidence_level="demonstrated",
        http_method="POST", endpoint="/rest/user/login",
        url="http://target.test/", reproduction="payload in email")
    session.add(row)
    session.flush()
    session.commit()
    return row


LOGIN_THEN_USERS = [
    {"label": "login", "method": "POST", "url": "http://target.test/rest/user/login",
     "headers": {"Content-Type": "application/json"},
     "body": '{"email":"\' OR 1=1--","password":"x"}',
     "extract": [{"var": "token", "from": "json", "path": "authentication.token"}]},
    {"label": "read admin", "method": "GET", "url": "http://target.test/api/Users/1",
     "headers": {"Authorization": "Bearer {{token}}"}},
]


def test_the_token_from_the_login_lands_in_the_next_request(env, monkeypatch):
    wire = FakeWire()
    monkeypatch.setattr(repeat.urllib.request, "urlopen", wire)
    _, _, session, org = env
    _grant(session, org, [{"type": "url", "value": "http://target.test/rest/user/login"}],
           ("active_verification", "intrusive_testing"))
    _grant(session, org, [{"type": "url", "value": "http://target.test/api/Users/1"}])

    outcome = repeat.run(session, org, LOGIN_THEN_USERS, actor="console",
                         principal="console")
    assert outcome["result"] == "ok", outcome["error"]
    assert [step["status"] for step in outcome["steps"]] == [200, 200]
    # The header that arrived on the wire carries the extracted token.
    assert wire.sent[1]["headers"]["Authorization"] == "Bearer jwt-from-login"
    # What is stored is what was written: the placeholder, not the secret.
    assert outcome["steps"][1]["request_headers"]["Authorization"] == "Bearer {{token}}"
    assert outcome["steps"][0]["extracted"]["token"]["chars"] == len("jwt-from-login")
    assert "admin" in outcome["steps"][1]["response_body"]


def test_an_unresolved_placeholder_stops_the_chain(env, monkeypatch):
    wire = FakeWire()
    monkeypatch.setattr(repeat.urllib.request, "urlopen", wire)
    _, _, session, org = env
    _grant(session, org, [{"type": "url", "value": "http://target.test/api/Users/1"}])

    outcome = repeat.run(session, org, [LOGIN_THEN_USERS[1]], actor="console",
                         principal="console")
    assert outcome["result"] == "error"
    assert "missing variable" in outcome["steps"][0]["error"]
    assert wire.sent == [], "nothing may be sent with a literal placeholder"


def test_no_grant_sends_nothing_and_says_so(env, monkeypatch):
    wire = FakeWire()
    monkeypatch.setattr(repeat.urllib.request, "urlopen", wire)
    _, _, session, org = env

    outcome = repeat.run(session, org, LOGIN_THEN_USERS[:1], actor="console",
                         principal="console")
    assert outcome["result"] == "denied"
    assert outcome["steps"][0]["authorized"] is False
    assert wire.sent == []


def test_a_mutating_step_also_needs_intrusive_testing(env, monkeypatch):
    wire = FakeWire()
    monkeypatch.setattr(repeat.urllib.request, "urlopen", wire)
    _, _, session, org = env
    _grant(session, org, [{"type": "url", "value": "http://target.test/rest/user/login"}])

    outcome = repeat.run(session, org, LOGIN_THEN_USERS[:1], actor="console",
                         principal="console")
    assert outcome["result"] == "denied"
    assert "intrusive_testing" in outcome["steps"][0]["error"]
    assert wire.sent == []


def test_the_chain_is_seeded_from_the_finding_and_its_login_profile(env):
    _, _, session, org = env
    profile = models.AuthProfile(
        org_id=org.id, name="customer", kind="form_login",
        headers=json.dumps({"Accept": "application/json"}),
        login_steps=json.dumps([{ "method": "POST",
                                 "url": "http://target.test/rest/user/login",
                                 "body": "{}",
                                 "extract": [{"var": "token", "from": "json",
                                              "path": "authentication.token"}]}]))
    session.add(profile)
    session.flush()
    finding = models.Finding(
        org_id=org.id, kind="vulnerability", fingerprint="fp-seed",
        source="pentest", title="IDOR", severity="high", status="open",
        triage_status="new", http_method="GET", endpoint="/api/Users/1",
        url="http://target.test/#/login", auth_profile_id=profile.id)
    session.add(finding)
    session.commit()

    steps = repeat.chain_from_finding(session, finding)
    assert [step["method"] for step in steps] == ["POST", "GET"]
    # The endpoint joins the host, never the client-side route.
    assert steps[1]["url"] == "http://target.test/api/Users/1"
    assert steps[1]["headers"] == {"Accept": "application/json"}
    assert steps[0]["extract"][0]["var"] == "token"


def test_running_a_chain_is_recorded_and_readable(env, monkeypatch):
    http, headers, session, org = env
    finding = _finding(session, org)
    _grant(session, org, [{"type": "url", "value": "http://target.test/rest/user/login"}],
           ("active_verification", "intrusive_testing"))
    _grant(session, org, [{"type": "url", "value": "http://target.test/api/Users/1"}])
    monkeypatch.setattr(repeat.urllib.request, "urlopen", FakeWire())

    body = http.post(f"/api/v1/findings/{finding.id}/repeat",
                     json={"steps": LOGIN_THEN_USERS, "actor": "console",
                           "principal": "console"}, headers=headers)
    assert body.status_code == 201, body.text
    run = body.json()["data"]
    assert run["result"] == "ok", run["error"]
    assert len(run["steps"]) == 2
    assert run["variables"]["token"]["chars"] > 0

    listed = http.get(f"/api/v1/findings/{finding.id}/repeat", headers=headers).json()
    assert listed["total"] == 1
    assert listed["data"][0]["steps"][1]["response_headers"]["Content-Type"] == "application/json"


def test_a_denied_run_is_kept_as_evidence(env, monkeypatch):
    http, headers, session, org = env
    finding = _finding(session, org)
    monkeypatch.setattr(repeat.urllib.request, "urlopen", FakeWire())
    body = http.post(f"/api/v1/findings/{finding.id}/repeat",
                     json={"steps": LOGIN_THEN_USERS[:1], "actor": "console",
                           "principal": "console"}, headers=headers)
    assert body.status_code == 201
    assert body.json()["data"]["result"] == "denied"
    assert http.get(f"/api/v1/findings/{finding.id}/repeat",
                    headers=headers).json()["total"] == 1


def test_a_chain_with_no_step_is_a_422(env):
    http, headers, session, org = env
    finding = models.Finding(org_id=org.id, kind="vulnerability", fingerprint="fp-empty",
                             source="manual", title="no request", severity="low",
                             status="open")
    session.add(finding)
    session.commit()
    response = http.post(f"/api/v1/findings/{finding.id}/repeat",
                         json={"steps": [], "actor": "console"}, headers=headers)
    assert response.status_code == 422
    assert "no chain" in response.json()["detail"]

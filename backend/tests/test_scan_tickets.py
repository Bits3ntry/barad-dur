"""v01 scan flows: minting, authorization and the executor contract.

The last test in this file feeds the minted ticket to the REAL Shauron intake code
(imported from the sibling repo) and requires it to accept it. That is the whole
point of the contract: two products, one envelope, proven on every build.
"""
import hashlib
import json
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models, scan_actions  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402
from backend.app.routers import scans as scans_router  # noqa: E402

CYB_ROOT = BACKEND_ROOT.parent.parent
SHAURON_ROOT = CYB_ROOT / "shauron"
COMMIT = "3f9a1c0b8d2e4f5a6b7c8d9e0f1a2b3c4d5e6f70"


@pytest.fixture()
def flow(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/scan.db")
    monkeypatch.delenv("SHAURON_DAEMON_URL", raising=False)
    monkeypatch.delenv("SCAN_SIGNING_KEY", raising=False)
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "scan")
    project = models.Project(org_id=org.id, slug="aurea", name="Aurea")
    repository = models.Repository(
        org_id=org.id, provider="github", name="aurea",
        remote_url="https://github.com/bitsentry/aurea")
    session.add_all([project, repository])
    session.flush()
    session.add(models.ProjectRepository(
        org_id=org.id, project_id=project.id, repository_id=repository.id,
        added_by="santiago"))
    session.commit()

    from fastapi.testclient import TestClient

    client = TestClient(app)
    ctx = {
        "client": client,
        "headers": {"X-API-Key": key},
        "org_id": org.id,
        "project": project.slug,
        "repository": repository.remote_url,
        "db": lambda: session_factory()(),
    }
    return ctx


def _mint(ctx, **overrides):
    body = {
        "action": "code",
        "project": ctx["project"],
        "commit": COMMIT,
        "origin": "ci",
        "actor": "santiago",
        "branch": "main",
    }
    body.update(overrides)
    return ctx["client"].post("/api/v1/scans", json=body, headers=ctx["headers"])


def test_mint_returns_a_ticket_that_shauron_accepts(flow):
    response = _mint(flow)
    assert response.status_code == 201, response.text
    data = response.json()
    ticket = data["ticket"]
    assert data["data"]["status"] == "requested"

    sys.path.insert(0, str(SHAURON_ROOT))
    from shauron import contract as shauron_contract
    from shauron.verify import verify

    assert shauron_contract.validate(ticket, "barad-ticket-v1") == []
    public = flow["client"].get("/api/v1/scans/key", headers=flow["headers"]).json()
    assert verify(ticket, public["data"]["public_key"]) == (True, "ok")
    assert ticket["authorization"]["decision"] == "push"
    assert ticket["tasks"][0]["capability"] == "vulnerability_analysis"


def test_shauron_intake_accepts_the_minted_ticket(flow):
    """End to end across the two repos, in process: mint here, validate there."""
    response = _mint(flow)
    ticket = response.json()["ticket"]
    public = flow["client"].get("/api/v1/scans/key", headers=flow["headers"]) \
        .json()["data"]["public_key"]

    sys.path.insert(0, str(SHAURON_ROOT))
    from fastapi.testclient import TestClient
    from shauron import manifest as manifest_module
    from shauron.intake.app import create_app as create_daemon
    from shauron.intake.store import Store

    daemon_app = create_daemon(
        store=Store(":memory:"), manifest=manifest_module.load(), public_key=public)
    client = TestClient(daemon_app)
    accepted = client.post("/tickets", json=ticket)
    assert accepted.status_code == 201, accepted.text
    assert accepted.json()["data"]["state"] == "accepted"
    # Idempotent: the same ticket never becomes a second run.
    again = client.post("/tickets", json=ticket)
    assert again.status_code == 200
    assert again.json()["data"]["run_id"] == accepted.json()["data"]["run_id"]


def test_console_scan_without_a_grant_is_denied(flow):
    response = _mint(flow, origin="console", actor="console")
    assert response.status_code == 403
    assert "not authorized" in response.json()["detail"]
    # A denial creates no flow: nothing to clean up later.
    listing = flow["client"].get("/api/v1/scans", headers=flow["headers"]).json()
    assert listing["counters"]["total"] == 0


def test_console_scan_with_a_grant_is_allowed(flow):
    grant = flow["client"].post("/api/v1/authorization/grants", json={
        "principal": "console",
        "capabilities": ["vulnerability_analysis"],
        "targets": [{"type": "repository", "value": flow["repository"]}],
        "issued_by": "santiago",
        "justification": "console scans",
        "actor": "santiago"}, headers=flow["headers"])
    assert grant.status_code in (200, 201), grant.text
    response = _mint(flow, origin="console", actor="console")
    assert response.status_code == 201, response.text
    ticket = response.json()["ticket"]
    assert ticket["authorization"]["decision"] == "allow"
    assert ticket["authorization"]["grant_id"]


def test_an_action_spanning_two_capabilities_needs_both(flow):
    """`authorize()` decides one capability per call, so a multi-capability
    action is evaluated one by one and EVERY one must pass. Joining them with a
    comma looked fine and silently denied — a regression this test pins."""
    targets = [{"type": "domain", "value": "aurea.com"}]
    first = flow["client"].post("/api/v1/authorization/grants", json={
        "principal": "console", "capabilities": ["passive_discovery"],
        "targets": targets, "issued_by": "santiago",
        "justification": "surface", "actor": "santiago"}, headers=flow["headers"])
    assert first.status_code in (200, 201), first.text

    partial = _mint(flow, action="web-surface", origin="console", actor="console",
                    targets=targets)
    assert partial.status_code == 403, partial.text
    assert "active_verification" in partial.json()["detail"]

    second = flow["client"].post("/api/v1/authorization/grants", json={
        "principal": "console", "capabilities": ["active_verification"],
        "targets": targets, "issued_by": "santiago",
        "justification": "surface probe", "actor": "santiago"},
        headers=flow["headers"])
    assert second.status_code in (200, 201), second.text

    complete = _mint(flow, action="web-surface", origin="console", actor="console",
                     targets=targets)
    assert complete.status_code == 201, complete.text
    ticket = complete.json()["ticket"]
    assert sorted(ticket["authorization"]["capabilities"]) == [
        "active_verification", "passive_discovery"]


def test_push_may_not_ask_for_network_capabilities(flow):
    response = _mint(flow, action="supply-chain")
    assert response.status_code == 422
    assert "push ticket" in response.json()["detail"]


def test_verified_secrets_is_never_a_push_action(flow):
    """Verification presents the credential to its issuer: that is the platform
    acting alone, so a CI/CLI push may never request it."""
    response = _mint(flow, action="secrets-verified")
    assert response.status_code == 422, response.text
    assert "networked" in response.json()["detail"]


def test_verified_secrets_asks_for_the_opt_in_provider_and_egress(flow):
    grant = flow["client"].post("/api/v1/authorization/grants", json={
        "principal": "console",
        "capabilities": ["vulnerability_analysis"],
        "targets": [{"type": "repository", "value": flow["repository"]}],
        "issued_by": "santiago",
        "justification": "verified secret sweep",
        "actor": "santiago"}, headers=flow["headers"])
    assert grant.status_code in (200, 201), grant.text

    response = _mint(flow, action="secrets-verified", origin="console",
                     actor="console")
    assert response.status_code == 201, response.text
    ticket = response.json()["ticket"]
    secrets = next(t for t in ticket["tasks"] if t["task"] == "secrets")
    # The task is unchanged — only the provider behind it is asked for by name.
    assert secrets["additional_providers"] == ["trufflehog"]
    assert secrets["contract"] == "sarif-2.1.0"
    assert ticket["execution"]["network"] is True

    catalog = flow["client"].get("/api/v1/scans/actions",
                                 headers=flow["headers"]).json()["data"]
    entry = next(a for a in catalog if a["name"] == "secrets-verified")
    assert entry["providers"] == {"secrets": ["trufflehog"]}
    assert entry["network"] is True


def test_the_verified_secrets_ticket_is_accepted_by_the_real_daemon(flow):
    """The opt-in provider must survive the whole hop: Barad mints it, Shauron's
    own schema and intake accept it, and the name is one the manifest serves."""
    grant = flow["client"].post("/api/v1/authorization/grants", json={
        "principal": "console",
        "capabilities": ["vulnerability_analysis"],
        "targets": [{"type": "repository", "value": flow["repository"]}],
        "issued_by": "santiago", "justification": "verified secrets",
        "actor": "santiago"}, headers=flow["headers"])
    assert grant.status_code in (200, 201), grant.text
    ticket = _mint(flow, action="secrets-verified", origin="console",
                   actor="console").json()["ticket"]
    public = flow["client"].get("/api/v1/scans/key", headers=flow["headers"]) \
        .json()["data"]["public_key"]

    sys.path.insert(0, str(SHAURON_ROOT))
    from fastapi.testclient import TestClient
    from shauron import contract as shauron_contract
    from shauron import manifest as manifest_module
    from shauron.intake.app import create_app as create_daemon
    from shauron.intake.store import Store

    assert shauron_contract.validate(ticket, "barad-ticket-v1") == []
    manifest = manifest_module.load()
    assert manifest.providers_for("secrets") == ["trivy", "gitleaks", "trufflehog"]

    daemon = TestClient(create_daemon(
        store=Store(":memory:"), manifest=manifest, public_key=public))
    accepted = daemon.post("/tickets", json=ticket)
    assert accepted.status_code == 201, accepted.text


def test_a_provider_the_daemon_does_not_serve_is_refused_by_name(flow):
    """A daemon that quietly ignores a requested provider would report a verified
    scan it never ran. The refusal names the provider."""
    grant = flow["client"].post("/api/v1/authorization/grants", json={
        "principal": "console",
        "capabilities": ["vulnerability_analysis"],
        "targets": [{"type": "repository", "value": flow["repository"]}],
        "issued_by": "santiago", "justification": "verified secrets",
        "actor": "santiago"}, headers=flow["headers"])
    assert grant.status_code in (200, 201), grant.text
    ticket = _mint(flow, action="secrets-verified", origin="console",
                   actor="console").json()["ticket"]
    public = flow["client"].get("/api/v1/scans/key", headers=flow["headers"]) \
        .json()["data"]["public_key"]

    sys.path.insert(0, str(SHAURON_ROOT))
    from fastapi.testclient import TestClient
    from shauron import manifest as manifest_module
    from shauron.intake.app import create_app as create_daemon
    from shauron.intake.store import Store

    # A daemon that ships without the opt-in provider.
    raw = json.loads(json.dumps(manifest_module.load().raw))
    raw["tasks"]["secrets"]["opt_in_providers"] = []
    trimmed = manifest_module.Manifest(raw=raw, path=Path("manifest.json"))

    daemon = TestClient(create_daemon(
        store=Store(":memory:"), manifest=trimmed, public_key=public))
    refused = daemon.post("/tickets", json=ticket)
    assert refused.status_code == 422, refused.text
    assert "trufflehog" in refused.text
    assert "provider" in refused.text.lower()


def test_action_without_a_bound_repository_is_refused(flow):
    session = flow["db"]()
    try:
        session.query(models.ProjectRepository).delete()
        session.commit()
    finally:
        session.close()
    response = _mint(flow)
    assert response.status_code == 422
    assert "no repository is bound" in response.json()["detail"]


def test_scan_without_an_exact_commit_is_refused(flow):
    response = _mint(flow, commit=None)
    assert response.status_code == 422
    assert "40-character sha" in response.json()["detail"]


def test_unknown_action_names_the_catalog(flow):
    response = _mint(flow, action="nuclei-everything")
    assert response.status_code == 422
    assert sorted(scan_actions.ACTIONS)[0] in response.json()["detail"]


def test_executor_routes_require_the_ticket_token(flow):
    ticket = _mint(flow).json()["ticket"]
    job_id = ticket["ticket_id"]
    body = {"schema": "barad-event-v1", "ticket_id": job_id, "event": "started"}
    assert flow["client"].post(f"/api/v1/scans/{job_id}/events", json=body).status_code == 401
    assert flow["client"].post(
        f"/api/v1/scans/{job_id}/events", json=body,
        headers={"X-Ticket-Token": "wrong"}).status_code == 401
    ok = flow["client"].post(f"/api/v1/scans/{job_id}/events", json=body,
                             headers={"X-Ticket-Token": ticket["evidence"]["upload_token"]})
    assert ok.status_code == 200 and ok.json()["data"]["status"] == "running"


def test_evidence_binds_to_the_flow_and_completes_it(flow):
    ticket = _mint(flow).json()["ticket"]
    job_id, token = ticket["ticket_id"], ticket["evidence"]["upload_token"]
    headers = {"X-Ticket-Token": token}

    for kind in ("sast", "secrets"):
        content = json.dumps({"kind": kind, "results": []})
        response = flow["client"].post(
            f"/api/v1/scans/{job_id}/evidence",
            json={"schema": "barad-evidence-v1", "ticket_id": job_id,
                  "kind": kind, "format": "sarif-2.1.0",
                  "content_hash": "sha256:" + hashlib.sha256(
                      content.encode()).hexdigest(),
                  "content": content, "tool": {"name": "opengrep",
                                               "version": "1.33.1"}},
            headers=headers)
        assert response.status_code == 201, response.text

    detail = flow["client"].get(f"/api/v1/scans/{job_id}",
                                headers=flow["headers"]).json()["data"]
    assert detail["evidence"] == "complete"
    assert {item["kind"] for item in detail["evidence_received"]} == {"sast", "secrets"}


def test_a_corrupted_artifact_is_refused(flow):
    ticket = _mint(flow).json()["ticket"]
    job_id, token = ticket["ticket_id"], ticket["evidence"]["upload_token"]
    response = flow["client"].post(
        f"/api/v1/scans/{job_id}/evidence",
        json={"schema": "barad-evidence-v1", "ticket_id": job_id,
              "kind": "sast", "format": "sarif-2.1.0",
              "content_hash": "sha256:" + "0" * 64, "content": "{}"},
        headers={"X-Ticket-Token": token})
    assert response.status_code == 409
    assert "evidence_corrupt" in response.json()["detail"]


def _sarif(*results) -> str:
    return json.dumps({"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "opengrep", "version": "1.33.1", "rules": [
            {"id": "python.lang.security.audit.eval", "shortDescription":
             {"text": "eval on user input"}}]}},
        "results": list(results)}]})


def _result(rule="python.lang.security.audit.eval", uri="app/server.py", line=42):
    return {"ruleId": rule, "level": "error",
            "message": {"text": "eval on user input"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": line}}}]}


def test_a_sarif_artifact_becomes_findings_attributed_to_the_flow(flow):
    """The scan's last mile: evidence in, findings out, one identity per finding."""
    minted = _mint(flow, version="0.4.2").json()
    ticket = minted["ticket"]
    job_id, token = ticket["ticket_id"], ticket["evidence"]["upload_token"]
    content = _sarif(_result(), _result(uri="app/models.py", line=7))
    posted = flow["client"].post(
        f"/api/v1/scans/{job_id}/evidence",
        json={"schema": "barad-evidence-v1", "ticket_id": job_id, "kind": "sast",
              "format": "sarif-2.1.0", "coverage": "full",
              "content_hash": "sha256:" + hashlib.sha256(content.encode()).hexdigest(),
              "content": content, "tool": {"name": "opengrep", "version": "1.33.1"},
              "evaluated": {"paths": ["app/"]}},
        headers={"X-Ticket-Token": token})
    assert posted.status_code == 201, posted.text
    ingested = posted.json()["data"]["ingested"]
    assert ingested["kind"] == "sast"
    assert ingested["counters"]["created"] == 2

    findings = flow["client"].get("/api/v1/findings?project=aurea",
                                  headers=flow["headers"]).json()
    rows = findings.get("data") or findings
    assert {row["path"] for row in rows} == {"app/server.py", "app/models.py"}
    assert all(row["kind"] == "code-weakness" for row in rows)

    # The analysis record points back at the flow, so the console can reopen it.
    session = flow["db"]()
    try:
        runs = session.query(models.AnalysisRun).filter_by(scan_job_id=job_id).all()
        assert len(runs) == 1
        assert runs[0].tool == "opengrep"
        assert runs[0].revision == COMMIT
    finally:
        session.close()


def test_the_flow_reports_its_own_result(flow):
    """What did this run produce? The answer is the findings whose last evaluation
    was one of the flow's own artifacts — not the project's whole backlog, and not
    "everything seen since"."""
    ticket = _mint(flow, version="0.4.2").json()["ticket"]
    job_id, token = ticket["ticket_id"], ticket["evidence"]["upload_token"]
    content = _sarif(_result(uri="app/models.py", line=7))
    posted = flow["client"].post(
        f"/api/v1/scans/{job_id}/evidence",
        json={"schema": "barad-evidence-v1", "ticket_id": job_id, "kind": "sast",
              "format": "sarif-2.1.0", "coverage": "full",
              "content_hash": "sha256:" + hashlib.sha256(content.encode()).hexdigest(),
              "content": content, "tool": {"name": "opengrep", "version": "1.33.1"},
              "evaluated": {"paths": ["app/"]}},
        headers={"X-Ticket-Token": token})
    assert posted.status_code == 201, posted.text

    result = flow["client"].get(f"/api/v1/scans/{job_id}/findings",
                                headers=flow["headers"])
    assert result.status_code == 200, result.text
    body = result.json()
    assert body["counters"]["total"] == 1
    assert body["data"][0]["path"] == "app/models.py"
    assert body["data"][0]["line"] == 7
    assert body["counters"]["by_severity"]

    # A flow that never delivered evidence reports an empty result, not an error.
    quiet = _mint(flow, commit="a" * 40).json()["ticket"]["ticket_id"]
    empty = flow["client"].get(f"/api/v1/scans/{quiet}/findings",
                               headers=flow["headers"]).json()
    assert empty["data"] == [] and empty["counters"]["total"] == 0


def test_the_same_artifact_twice_is_not_two_findings(flow):
    minted = _mint(flow, version="0.4.2").json()
    ticket = minted["ticket"]
    job_id, token = ticket["ticket_id"], ticket["evidence"]["upload_token"]
    content = _sarif(_result())
    body = {"schema": "barad-evidence-v1", "ticket_id": job_id, "kind": "sast",
            "format": "sarif-2.1.0",
            "content_hash": "sha256:" + hashlib.sha256(content.encode()).hexdigest(),
            "content": content}
    first = flow["client"].post(f"/api/v1/scans/{job_id}/evidence", json=body,
                                headers={"X-Ticket-Token": token})
    second = flow["client"].post(f"/api/v1/scans/{job_id}/evidence", json=body,
                                 headers={"X-Ticket-Token": token})
    assert first.status_code == 201 and second.status_code == 201
    assert second.json()["data"].get("duplicate") is True

    session = flow["db"]()
    try:
        assert session.query(models.Finding).filter_by(project_id=(
            session.query(models.Project).filter_by(slug="aurea").one().id)).count() == 1
    finally:
        session.close()


def test_a_raw_sarif_body_reaches_the_findings_pipeline(flow):
    """The transport the CLI actually uses for a real SARIF: artifact as body.

    The JSON envelope is tested above; this pins the other half, because a
    megabyte of rule metadata must not be the difference between a scan that
    produces findings and one that does not.
    """
    minted = _mint(flow, version="0.4.2").json()
    ticket = minted["ticket"]
    job_id, token = ticket["ticket_id"], ticket["evidence"]["upload_token"]
    body = _sarif(_result(uri="app/raw.py", line=9)).encode()
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    query = ("kind=sast&format=sarif-2.1.0&coverage=full"
             f"&hash={digest}&tool=%7B%22name%22%3A%22opengrep%22%7D"
             "&evaluated=%7B%22paths%22%3A%5B%22app%2F%22%5D%7D")
    response = flow["client"].post(
        f"/api/v1/scans/{job_id}/evidence?{query}",
        content=body,
        headers={"X-Ticket-Token": token,
                 "Content-Type": "application/octet-stream"})
    assert response.status_code == 201, response.text
    assert response.json()["data"]["ingested"]["counters"]["created"] == 1

    findings = flow["client"].get("/api/v1/findings?project=aurea",
                                  headers=flow["headers"]).json()
    rows = findings.get("data") or findings
    assert [row["path"] for row in rows] == ["app/raw.py"]


def test_a_raw_body_without_its_metadata_is_refused_by_name(flow):
    ticket = _mint(flow).json()["ticket"]
    response = flow["client"].post(
        f"/api/v1/scans/{ticket['ticket_id']}/evidence?kind=sast",
        content=b"{}",
        headers={"X-Ticket-Token": ticket["evidence"]["upload_token"],
                 "Content-Type": "application/octet-stream"})
    assert response.status_code == 422
    assert "format" in response.json()["detail"]


def test_the_platform_contract_version_matches_shauron():
    version_file = SHAURON_ROOT / "shauron" / "VERSION"
    if not version_file.exists():
        pytest.skip("shauron repo not checked out next to barad-dur")
    assert scans_router.SUPPORTED_CONTRACT == version_file.read_text().strip()

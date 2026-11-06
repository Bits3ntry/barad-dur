"""Pipeline rows: an Action run is a flow, and its verdict is fail-closed.

The screen answers one question — "what did the pipeline do?" — so this file
pins the three things that make the answer honest: a run that has not finished is
`running` (never `pass`), a finished run whose evidence is incomplete fails
because it cannot certify anything, and a finding at or above HIGH fails the run
the same way `ci.finish_run` fails a registered one. A scan started by hand is a
scanner run and must not appear here at all.
"""
import json
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models, pipeline  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402

COMMIT = "3f9a1c0b8d2e4f5a6b7c8d9e0f1a2b3c4d5e6f70"


@pytest.fixture()
def flow(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/pipeline.db")
    monkeypatch.delenv("SHAURON_DAEMON_URL", raising=False)
    monkeypatch.delenv("SCAN_SIGNING_KEY", raising=False)
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "pipeline")
    project = models.Project(org_id=org.id, slug="aurea", name="Aurea")
    repository = models.Repository(
        org_id=org.id, provider="gitea", name="aurea-server",
        remote_url="https://gitea.example/bitsentry/aurea-server.git")
    session.add_all([project, repository])
    session.flush()
    session.add(models.ProjectRepository(
        org_id=org.id, project_id=project.id, repository_id=repository.id,
        added_by="santiago"))
    # A ticket resolves its component through the repository: without one
    # mapping the platform files the flow as needs-attribution instead.
    component = models.ApplicationComponent(
        org_id=org.id, project_id=project.id, name="Aurea service",
        slug="aurea-server", kind="service")
    session.add(component)
    session.flush()
    session.add(models.ComponentRepository(
        org_id=org.id, component_id=component.id, repository_id=repository.id,
        added_by="santiago"))
    session.commit()

    from fastapi.testclient import TestClient

    return {"client": TestClient(app), "headers": {"X-API-Key": key},
            "org_id": org.id, "project_id": project.id,
            "db": lambda: session_factory()()}


def _mint(ctx, **overrides):
    body = {"action": "code", "project": "aurea", "commit": COMMIT,
            "branch": "main", "origin": "ci", "actor": "santiago"}
    body.update(overrides)
    response = ctx["client"].post("/api/v1/scans", json=body, headers=ctx["headers"])
    assert response.status_code == 201, response.text
    return response.json()


def _close(ctx, job_id, status="finished", evidence="complete"):
    session = ctx["db"]()
    try:
        job = session.get(models.ScanJob, job_id)
        job.status = status
        job.evidence_state = evidence
        job.finished_at = models.utcnow()
        session.commit()
    finally:
        session.close()


def _finding(ctx, job_id, severity="CRITICAL", status="open"):
    session = ctx["db"]()
    try:
        job = session.get(models.ScanJob, job_id)
        run = models.AnalysisRun(org_id=job.org_id, project_id=ctx["project_id"],
                                 tool="opengrep", coverage="full", source="scan",
                                 scan_job_id=job.id)
        session.add(run)
        session.flush()
        session.add(models.Finding(
            org_id=job.org_id, project_id=ctx["project_id"], kind="sast",
            fingerprint=f"sast:{job.id}", source="scan", severity=severity,
            title="interpolated query", status=status,
            last_evaluated_run_id=run.id))
        session.commit()
    finally:
        session.close()


def _finished_event(ctx, job_id, findings):
    """The executor's own counters, the way a real run leaves them behind."""
    session = ctx["db"]()
    try:
        job = session.get(models.ScanJob, job_id)
        session.add(models.ScanEvent(
            org_id=job.org_id, job_id=job.id, seq=99, kind="finished",
            source="executor", at_server=models.utcnow(),
            detail=json.dumps({"counts": {"findings": findings}, "duration_s": 12.5})))
        session.commit()
    finally:
        session.close()


def _rows(ctx):
    response = ctx["client"].get("/api/v1/pipeline/actions", headers=ctx["headers"])
    assert response.status_code == 200, response.text
    return response.json()


def _groups(ctx, **params):
    """The screen's own shape: runs folded into one row per commit."""
    response = ctx["client"].get("/api/v1/pipeline/commits", params=params,
                                headers=ctx["headers"])
    assert response.status_code == 200, response.text
    return response.json()


def test_an_unfinished_action_is_running_and_names_its_workflow_event(flow):
    minted = _mint(flow)
    body = _rows(flow)
    assert body["total"] == 1
    row = body["data"][0]
    assert row["id"] == minted["ticket"]["ticket_id"]
    assert row["verdict"] == "running"
    assert row["ref"] == "main"
    assert row["event"] == "push"
    assert row["commit"] == COMMIT
    # The commit is a link a reader can follow to the forge, not a dead hash.
    assert row["commit_url"].endswith(f"/commit/{COMMIT}")
    assert row["repository_url"] == "https://gitea.example/bitsentry/aurea-server"
    assert row["actor"] == "santiago"
    # The action is read back from the tasks the ticket asked for.
    assert row["action"] == "code"
    assert row["findings"]["total"] == 0
    assert body["counters"] == {"running": 1, "pass": 0, "fail": 0, "superseded": 0}


def test_a_pull_request_ticket_reports_the_pull_request_event(flow):
    _mint(flow, pull_request="42", pull_request_author="ana")
    row = _rows(flow)["data"][0]
    assert row["event"] == "pull_request"
    assert row["pull_request"] == "42"
    # Who opened the PR travels with the run: the console asks the author.
    assert row["pull_request_author"] == "ana"


def test_commit_links_follow_each_forge_and_transport():
    sha = "abc123"
    https = "https://gitea.example/bitsentry/aurea-server.git"
    assert pipeline.commit_url(https, sha) == \
        "https://gitea.example/bitsentry/aurea-server/commit/abc123"
    assert pipeline.commit_url("https://github.com/bitsentry/aurea.git", sha) == \
        "https://github.com/bitsentry/aurea/commit/abc123"
    assert pipeline.commit_url("https://gitlab.com/bitsentry/aurea.git", sha) == \
        "https://gitlab.com/bitsentry/aurea/-/commit/abc123"
    assert pipeline.commit_url("https://bitbucket.org/bitsentry/aurea.git", sha) == \
        "https://bitbucket.org/bitsentry/aurea/commits/abc123"
    # scp-style and ssh remotes are the same repository as their web page.
    assert pipeline.commit_url("git@gitea.example:bitsentry/aurea.git", sha) == \
        "https://gitea.example/bitsentry/aurea/commit/abc123"
    assert pipeline.commit_url("ssh://git@gitea.example/bitsentry/aurea.git", sha) == \
        "https://gitea.example/bitsentry/aurea/commit/abc123"
    # Nothing usable means no link, never a guessed host.
    assert pipeline.commit_url(None, sha) is None
    assert pipeline.commit_url("file:///src/aurea", sha) is None
    assert pipeline.commit_url(https, None) is None


def test_complete_evidence_without_high_findings_passes(flow):
    minted = _mint(flow)
    job_id = minted["ticket"]["ticket_id"]
    _finding(flow, job_id, severity="MEDIUM")
    _close(flow, job_id)
    body = _rows(flow)
    row = body["data"][0]
    assert row["verdict"] == "pass"
    assert row["findings"]["total"] == 1
    assert row["findings"]["worst"] == "MEDIUM"
    assert body["counters"]["pass"] == 1


def test_a_high_finding_fails_the_action(flow):
    minted = _mint(flow)
    job_id = minted["ticket"]["ticket_id"]
    _finding(flow, job_id, severity="CRITICAL")
    _close(flow, job_id)
    row = _rows(flow)["data"][0]
    assert row["verdict"] == "fail"
    assert "CRITICAL" in row["verdict_reason"]
    assert row["findings"]["by_severity"] == {"CRITICAL": 1}


def test_incomplete_evidence_cannot_certify_a_pass(flow):
    minted = _mint(flow)
    _close(flow, minted["ticket"]["ticket_id"], evidence="partial")
    row = _rows(flow)["data"][0]
    assert row["verdict"] == "fail"
    assert "partial" in row["verdict_reason"]


def test_a_scanner_run_started_by_hand_is_not_a_pipeline_row(flow):
    # A push ticket from the CLI needs no grant; the console one would, and the
    # point here is the origin, not authorization.
    _mint(flow, origin="cli", actor="santiago")
    _mint(flow, origin="cli", actor="ana", commit="a" * 40)
    body = _rows(flow)
    assert body["total"] == 0
    assert body["counters"] == {"running": 0, "pass": 0, "fail": 0, "superseded": 0}


def test_the_gate_route_answers_the_runner_with_its_own_verdict(flow):
    """The ticket token is the credential a pipeline actually holds."""
    minted = _mint(flow)
    job_id = minted["ticket"]["ticket_id"]
    headers = {"X-Ticket-Token": minted["ticket"]["evidence"]["upload_token"]}

    gate = flow["client"].get(f"/api/v1/scans/{job_id}/gate", headers=headers)
    assert gate.status_code == 200, gate.text
    assert gate.json()["data"]["verdict"] == "running"

    _finding(flow, job_id, severity="CRITICAL")
    _close(flow, job_id)
    data = flow["client"].get(f"/api/v1/scans/{job_id}/gate", headers=headers).json()["data"]
    assert data["verdict"] == "fail"
    assert "CRITICAL" in data["reason"]
    # Same numbers the console shows: one count, one decision.
    assert _rows(flow)["data"][0]["verdict"] == "fail"


def test_the_gate_route_refuses_without_the_ticket_token(flow):
    minted = _mint(flow)
    response = flow["client"].get(f"/api/v1/scans/{minted['ticket']['ticket_id']}/gate")
    assert response.status_code == 401


def test_a_closed_finding_does_not_block_the_gate(flow):
    """A build that never goes green gets switched off, so closed findings stop
    counting once they are closed."""
    minted = _mint(flow)
    job_id = minted["ticket"]["ticket_id"]
    _finding(flow, job_id, severity="CRITICAL", status="accepted_risk")
    _close(flow, job_id)
    _finished_event(flow, job_id, findings=1)
    row = _rows(flow)["data"][0]
    assert row["findings"]["total"] == 0
    # Still accounted for: the console lists it, the gate does not count it.
    assert row["findings"]["closed"] == 1
    # It still owns that finding: a pass, not a "somebody else evaluated this".
    assert row["superseded"] is False
    assert row["verdict"] == "pass"


def test_a_suppressed_finding_does_not_block_the_gate(flow):
    # `suppressed` is a status the suppression rules write, not part of the
    # finding's own vocabulary — silencing a finding must unblock the build too.
    minted = _mint(flow)
    job_id = minted["ticket"]["ticket_id"]
    _finding(flow, job_id, severity="HIGH", status="suppressed")
    _close(flow, job_id)
    assert _rows(flow)["data"][0]["verdict"] == "pass"


def test_an_older_run_whose_findings_moved_is_marked_re_evaluated(flow):
    """A finding belongs to the run that last evaluated it, so a newer run of the
    same commit takes it. The old row must not claim a pass it did not earn."""
    first = _mint(flow)["ticket"]["ticket_id"]
    _finding(flow, first, severity="HIGH")
    _close(flow, first)
    _finished_event(flow, first, findings=1)

    second = _mint(flow)["ticket"]["ticket_id"]
    session = flow["db"]()
    try:
        job = session.get(models.ScanJob, second)
        run = models.AnalysisRun(org_id=job.org_id, project_id=flow["project_id"],
                                 tool="trivy", coverage="full", source="scan",
                                 scan_job_id=job.id)
        session.add(run)
        session.flush()
        # The newer run re-evaluated the same finding and now owns it.
        finding = session.query(models.Finding).one()
        finding.last_evaluated_run_id = run.id
        session.commit()
    finally:
        session.close()

    rows = {row["id"]: row for row in _rows(flow)["data"]}
    old = rows[first]
    assert old["superseded"] is True
    assert old["findings"]["total"] == 0
    # What it reported at the time stays readable instead of collapsing to zero.
    assert old["findings"]["reported"] == 1


# ── one row per commit ───────────────────────────────────────────────────────
# A workflow that is retried or re-run leaves several executions on one sha. The
# screen groups them, and the grouping is only honest if a green retry cannot
# hide the red attempt behind it.


def test_runs_of_the_same_commit_fold_into_one_row_newest_first(flow):
    first = _mint(flow)["ticket"]["ticket_id"]
    _close(flow, first)
    second = _mint(flow)["ticket"]["ticket_id"]
    _close(flow, second)

    body = _groups(flow)
    assert body["total"] == 1
    group = body["data"][0]
    assert group["commit"] == COMMIT
    assert group["counts"]["total"] == 2
    # The row speaks with its newest run: that is the one holding today's findings.
    assert group["id"] == second
    assert [run["id"] for run in group["runs"]] == [second, first]


def test_a_green_retry_does_not_bury_the_red_attempt_behind_it(flow):
    first = _mint(flow)["ticket"]["ticket_id"]
    _finding(flow, first, severity="HIGH")
    _close(flow, first)
    second = _mint(flow)["ticket"]["ticket_id"]
    _close(flow, second)

    group = _groups(flow)["data"][0]
    # The commit's headline is the newest run, which found nothing...
    assert group["verdict"] == "pass"
    # ...and the earlier failure is still on the row instead of being averaged away.
    assert group["earlier_failed"] == 1
    assert group["runs"][-1]["verdict"] == "fail"
    assert group["counts"] == {"total": 2, "pass": 1, "fail": 1,
                              "running": 0, "superseded": 0}


def test_commits_page_by_commit_and_never_cut_a_group_in_half(flow):
    for sha in ("a" * 40, "b" * 40, "c" * 40):
        for _ in range(2):
            _close(flow, _mint(flow, commit=sha)["ticket"]["ticket_id"])

    first_page = _groups(flow, limit=2, offset=0)
    assert first_page["total"] == 3
    assert len(first_page["data"]) == 2
    assert all(len(group["runs"]) == 2 for group in first_page["data"])
    # Counters describe the pipeline, not the page: six runs, three commits.
    assert first_page["counters"]["runs"] == 6
    assert first_page["counters"]["commits"] == 3

    second_page = _groups(flow, limit=2, offset=2)
    assert len(second_page["data"]) == 1
    assert {group["commit"] for group in first_page["data"]}.isdisjoint(
        {group["commit"] for group in second_page["data"]})


def test_a_run_without_a_commit_is_its_own_row():
    """Two unstamped runs are not the same build, so they never merge."""
    assert pipeline.group_key({"id": "run-a", "commit": None}) == ("", "run-a")
    assert pipeline.group_key({"id": "run-b", "commit": None}) == ("", "run-b")
    # The repository is half the identity: two repos may hold the same sha.
    assert pipeline.group_key(
        {"id": "x", "commit": "sha", "repository_url": "https://one"}) == ("https://one", "sha")
    assert pipeline.group_key(
        {"id": "y", "commit": "sha", "repository_url": "https://two"}) == ("https://two", "sha")


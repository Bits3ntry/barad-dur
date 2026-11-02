"""v0 analysis coverage: what a run may close, and the finding timeline.

The spec's rule is narrow and testable: a partial import or a diff analysis must
not close findings it did not evaluate. These tests pin the gate, the tool match,
the path narrowing, and the history that records every decision.
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
def seeded(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/analysis.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="bitsentry", name="Bitsentry")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    project = models.Project(org_id=org.id, name="AUREA", slug="aurea")
    other_project = models.Project(org_id=other.id, name="Other", slug="other")
    session.add_all([project, other_project])
    session.flush()
    version = models.ProjectVersion(project_id=project.id, version="v3")
    session.add(version)
    session.flush()

    def finding(**kwargs):
        defaults = dict(org_id=org.id, project_id=project.id, kind="code-weakness",
                        source="cli", severity="HIGH", status="open",
                        last_seen_version_id=version.id,
                        first_seen_at=models.utcnow(), last_seen_at=models.utcnow())
        defaults.update(kwargs)
        row = models.Finding(fingerprint=f"fp-{kwargs.get('title', 'x')}", **defaults)
        session.add(row)
        session.flush()
        return row

    target = finding(title="SQL injection", tool="opengrep",
                     path="app/api/reports.py")
    outside = finding(title="Hardcoded password", tool="opengrep",
                      path="app/web/config.py")
    other_tool = finding(title="Vulnerable dependency", tool="trivy",
                         path="requirements.txt", severity="MEDIUM")
    resolved = finding(title="Already fixed", tool="opengrep",
                       path="app/api/old.py", status="resolved")
    suppressed = finding(title="Suppressed rule", tool="opengrep",
                         path="app/api/rules.py", status="suppressed")
    unborn = finding(title="Inconclusive", tool="inconclusive-tool",
                     path="app/api/x.py")
    session.commit()
    key = create_key(session, org.id, "analysis")
    other_key = create_key(session, other.id, "analysis-other")
    session.commit()

    from fastapi.testclient import TestClient
    return (TestClient(app), {"X-API-Key": key}, {"X-API-Key": other_key},
            session_factory, {"target": target.id, "outside": outside.id,
                              "other_tool": other_tool.id, "resolved": resolved.id,
                              "suppressed": suppressed.id, "unborn": unborn.id})


def _run(test_client, headers, **overrides):
    body = {"project": "aurea", "version": "v3", "tool": "opengrep",
            "tool_version": "1.33.1", "coverage": "full",
            "source": "import", "revision": "abc123",
            "evaluated": {"paths": ["app/api"]}, "findings_seen": 2,
            "actor": "tester"}
    body.update(overrides)
    response = test_client.post("/api/v1/analysis/runs", json=body, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()["data"]


def test_diff_and_partial_runs_cannot_close_anything(seeded):
    test_client, headers, _other, _sf, ids = seeded
    for coverage in ("diff", "partial", "unknown"):
        run = _run(test_client, headers, coverage=coverage)
        assert run["closure_eligible"] is False
        preview = test_client.post(
            f"/api/v1/analysis/runs/{run['id']}/close-unseen",
            json={"dry_run": True}, headers=headers)
        assert preview.status_code == 409
        assert "coverage is" in preview.json()["detail"]

    # Nothing changed.
    detail = test_client.get(f"/api/v1/findings/{ids['target']}", headers=headers).json()["data"]
    assert detail["status"] == "open"


def test_full_run_closes_only_what_it_evaluated(seeded):
    test_client, headers, _other, sf, ids = seeded
    run = _run(test_client, headers)
    assert run["closure_eligible"] is True

    preview = test_client.post(f"/api/v1/analysis/runs/{run['id']}/close-unseen",
                               json={"dry_run": True}, headers=headers)
    assert preview.status_code == 200, preview.text
    plan = preview.json()["data"]
    assert [item["id"] for item in plan["closable"]] == [ids["target"]]
    reasons = {item["id"]: item["reason"] for item in plan["skipped"]}
    assert "outside this run's evaluated paths" in reasons[ids["outside"]]
    assert "not by opengrep" in reasons[ids["other_tool"]]
    assert reasons[ids["resolved"]] == "status is resolved"
    assert reasons[ids["suppressed"]] == "status is suppressed"

    session = sf()()
    assert session.get(models.Finding, ids["target"]).status == "open"
    session.close()

    applied = test_client.post(f"/api/v1/analysis/runs/{run['id']}/close-unseen",
                               json={"dry_run": False, "actor": "tester"},
                               headers=headers).json()["data"]
    assert applied["changed"] == 1

    session = sf()()
    closed = session.get(models.Finding, ids["target"])
    assert closed.status == "resolved"
    assert closed.last_evaluated_run_id == run["id"]
    assert "full coverage" in closed.status_reason
    assert session.get(models.Finding, ids["outside"]).status == "open"
    assert session.get(models.Finding, ids["other_tool"]).status == "open"
    assert session.get(models.Finding, ids["unborn"]).status == "open"
    session.close()

    history = test_client.get(f"/api/v1/findings/{ids['target']}/history",
                              headers=headers).json()["data"]
    assert history[0]["action"] == "finding.closed_by_analysis"
    assert history[0]["actor"] == "tester"


def test_run_recording_is_validated_and_isolated(seeded):
    test_client, headers, other_headers, _sf, _ids = seeded
    bad_coverage = test_client.post("/api/v1/analysis/runs", json={
        "project": "aurea", "tool": "opengrep", "coverage": "everything"},
        headers=headers)
    assert bad_coverage.status_code == 422
    missing_version = test_client.post("/api/v1/analysis/runs", json={
        "project": "aurea", "version": "v9", "tool": "opengrep"}, headers=headers)
    assert missing_version.status_code == 404

    run = _run(test_client, headers)
    assert test_client.get(f"/api/v1/analysis/runs/{run['id']}",
                           headers=other_headers).status_code == 404
    assert test_client.post(f"/api/v1/analysis/runs/{run['id']}/close-unseen",
                            json={"dry_run": False},
                            headers=other_headers).status_code == 404
    assert test_client.get("/api/v1/analysis/runs",
                           headers=other_headers).json()["total"] == 0


def test_history_merges_audit_sightings_and_comments(seeded):
    test_client, headers, other_headers, _sf, ids = seeded
    finding_id = ids["target"]
    test_client.post(f"/api/v1/findings/{finding_id}/comments", json={
        "body": "reproduced locally", "author": "ana@bitsentry.xyz"}, headers=headers)
    test_client.patch(f"/api/v1/findings/{finding_id}/status", json={
        "status": "acknowledged", "reason": "triaged", "actor": "ana@bitsentry.xyz"}, headers=headers)

    history = test_client.get(f"/api/v1/findings/{finding_id}/history",
                              headers=headers).json()
    kinds = {event["kind"] for event in history["data"]}
    assert {"audit", "comment"} <= kinds
    assert history["first_seen_at"] and history["last_seen_at"]
    assert test_client.get(f"/api/v1/findings/{finding_id}/history",
                           headers=other_headers).status_code == 404

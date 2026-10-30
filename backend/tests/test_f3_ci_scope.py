"""F3 acceptance tests: CI registry with gate verdicts and static scope."""
import json
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.ci import finish_run, register_run  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


def test_verdict_pass_with_only_low_findings(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/v1.db")
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    project = models.Project(org_id=org.id, slug="fixture", name="fixture")
    session.add(project)
    session.flush()
    version_row = models.ProjectVersion(project_id=project.id, version="1.0")
    session.add(version_row)
    session.flush()
    component = models.Component(org_id=org.id, identity_key="pkg:pypi/x@1.0",
                                 purl="pkg:pypi/x@1.0", name="x")
    session.add(component)
    session.flush()
    run = register_run(session, org.id, provider="github", repository="councilbox/fixture",
                       workflow_path=None, ref="refs/heads/main", commit_sha="a" * 40,
                       event="push", actor="santiago")
    finding = models.Finding(
        org_id=org.id, project_id=project.id, kind="vulnerability",
        fingerprint="fp-low", source="osv", title="low thing", severity="LOW",
        component_id=component.id, last_seen_version_id=version_row.id,
        first_seen_at=models.utcnow(), last_seen_at=models.utcnow(),
        updated_at=models.utcnow())
    session.add(finding)
    session.flush()
    from backend.app import ci as ci_service

    ci_service.attach_finding(session, run, finding)
    summary = finish_run(session, run, status="succeeded")
    session.commit()
    assert summary["verdict"] == "pass"
    assert summary["findings_count"] == 1
    assert "none at or above HIGH" in run.verdict_detail
    session.close()


def test_verdict_fails_closed_with_high_findings_and_caps_reasons(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/v2.db")
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    project = models.Project(org_id=org.id, slug="fixture", name="fixture")
    session.add(project)
    session.flush()
    run = register_run(session, org.id, provider="github", repository="councilbox/fixture",
                       workflow_path=None, ref="refs/heads/main", commit_sha="b" * 40,
                       event="push", actor="santiago")
    rows = []
    for index in range(7):
        finding = models.Finding(
            org_id=org.id, project_id=project.id, kind="secret",
            fingerprint=f"fp-high-{index}", source="osv", title="leak",
            severity="HIGH", rule_id=f"rule-{index}", path=f"file-{index}.py",
            first_seen_at=models.utcnow(), last_seen_at=models.utcnow(),
            updated_at=models.utcnow())
        session.add(finding)
        session.flush()
        rows.append(finding)
    for finding in rows:
        (session.query(models.CiRunFinding)
         .filter_by(run_id=run.id).one_or_none())
        session.add(models.CiRunFinding(run_id=run.id, finding_id=finding.id,
                                        severity="HIGH", created_at=models.utcnow()))
    session.commit()
    summary = finish_run(session, run, status="succeeded")
    session.commit()
    assert summary["verdict"] == "fail"
    reasons = run.verdict_detail.splitlines()[1:]
    # Hard cap: the verdict renders in public CI logs.
    assert len(reasons) == 5
    assert all(line.startswith("HIGH secret") for line in reasons)
    session.close()


def test_failed_scan_never_passes(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/v3.db")
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    session.add(models.Project(org_id=org.id, slug="fixture", name="fixture"))
    session.flush()
    run = register_run(session, org.id, provider="github", repository="councilbox/fixture",
                       workflow_path=None, ref=None, commit_sha=None,
                       event="push", actor="santiago")
    summary = finish_run(session, run, status="failed")
    session.commit()
    assert summary["verdict"] == "fail"
    assert run.verdict_detail == "CI run reported failure"
    session.close()


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/f3.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "f3")
    project = models.Project(org_id=org.id, slug="fixture", name="fixture")
    session.add(project)
    session.flush()
    session.add(models.ProjectVersion(project_id=project.id, version="1.0"))
    session.commit()
    from fastapi.testclient import TestClient

    return TestClient(app), key, session


def test_ingest_with_run_id_and_full_ci_flow(client):
    test_client, key, session = client
    register_response = test_client.post(
        "/api/v1/ci/runs", headers={"X-API-Key": key},
        json={"provider": "github", "repository": "councilbox/f2-fixture",
              "ref": "refs/heads/main", "commit_sha": "a" * 40,
              "event": "push", "actor": "santiago"})
    assert register_response.status_code == 200, register_response.text
    run_id = register_response.json()["data"]["id"]

    ingest = test_client.post(
        "/api/v1/findings/ingest?project=fixture&version=1.0&source=ci&run_id=" + run_id,
        json={"schema": "barad-findings-v1", "tool": "trivy", "findings": [
            {"kind": "secret", "title": "AWS key", "severity": "HIGH",
             "rule_id": "aws-access-key-id", "path": "settings.py"}]},
        headers={"X-API-Key": key})
    assert ingest.status_code == 200
    finish = test_client.post(f"/api/v1/ci/runs/{run_id}/finish",
                              json={"status": "succeeded"},
                              headers={"X-API-Key": key})
    assert finish.status_code == 200, finish.text
    body = finish.json()["data"]
    assert body["verdict"] == "fail"
    assert body["findings_count"] == 1
    detail = test_client.get(f"/api/v1/ci/runs/{run_id}", headers={"X-API-Key": key}).json()["data"]
    assert detail["verdict_reasons"] == ["gate: findings at or above HIGH",
                                         "HIGH secret aws-access-key-id settings.py"]
    assert detail["findings"][0]["kind"] == "secret"

    pipelines = test_client.get("/api/v1/ci/pipelines", headers={"X-API-Key": key}).json()
    assert pipelines["total"] == 1
    assert pipelines["data"][0]["repository"] == "councilbox/f2-fixture"


def test_ci_run_finish_is_one_shot(client):
    test_client, key, session = client
    run_id = test_client.post("/api/v1/ci/runs", headers={"X-API-Key": key},
                              json={"repository": "councilbox/fixture"}).json()["data"]["id"]
    first = test_client.post(f"/api/v1/ci/runs/{run_id}/finish", json={"status": "succeeded"},
                             headers={"X-API-Key": key})
    second = test_client.post(f"/api/v1/ci/runs/{run_id}/finish", json={"status": "succeeded"},
                              headers={"X-API-Key": key})
    assert first.status_code == 200
    assert second.status_code == 409
    assert "only running" in second.json()["detail"]


def test_scope_targets_exclusions_and_resolved(client):
    test_client, key, session = client
    for entry in ({"target_type": "repository", "value": "councilbox/server"},
                  {"target_type": "service", "value": "sso-api"},
                  {"target_type": "host", "value": "10.0.0.0/8", "note": "internal"}):
        response = test_client.post("/api/v1/scope/targets", json=entry,
                                    headers={"X-API-Key": key})
        assert response.status_code == 200
    excluded = test_client.post(
        "/api/v1/scope/exclusions",
        json={"target_type": "host", "value": "10.0.0.0/8", "reason": "third-party monitored"},
        headers={"X-API-Key": key})
    assert excluded.status_code == 200
    no_reason = test_client.post(
        "/api/v1/scope/exclusions",
        json={"target_type": "host", "value": "1.2.3.4"},
        headers={"X-API-Key": key})
    assert no_reason.status_code == 422

    resolved = test_client.get("/api/v1/scope/resolved", headers={"X-API-Key": key}).json()
    assert resolved["total"] == 2
    assert resolved["excluded_count"] == 1
    values = {row["value"] for row in resolved["data"]}
    assert values == {"councilbox/server", "sso-api"}
    breadth = test_client.post(
        "/api/v1/scope/targets", json={"target_type": "alien", "value": "x"},
        headers={"X-API-Key": key})
    assert breadth.status_code == 422

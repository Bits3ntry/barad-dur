"""Schedules (tick) and the printable pentest report."""
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
def sched_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/sched.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    key = create_key(session, org.id, "sched")
    other_key = create_key(session, other.id, "sched2")
    session.commit()
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key}, {"X-API-Key": other_key})


def _setup(test_client, headers, grant=True):
    test_client.post("/api/v1/orchestration/scanners", json={
        "name": "trivy", "display_name": "Trivy",
        "capability": "vulnerability_analysis", "actor": "santiago"}, headers=headers)
    if grant:
        response = test_client.post("/api/v1/authorization/grants", json={
            "principal": "ci", "capabilities": ["vulnerability_analysis"],
            "targets": [{"type": "repository", "value": "acme/saria"}],
            "tools": ["trivy"], "environment": "ci", "issued_by": "santiago",
            "justification": "nightly", "actor": "santiago"}, headers=headers)
        assert response.status_code in (200, 201), response.text


def test_tick_queues_once_per_interval(sched_client):
    test_client, headers, _other = sched_client
    _setup(test_client, headers)
    created = test_client.post("/api/v1/orchestration/schedules", json={
        "name": "nightly", "scanner": "trivy",
        "capability": "vulnerability_analysis", "principal": "ci",
        "targets": [{"type": "repository", "value": "acme/saria"}],
        "environment": "ci", "interval_minutes": 60, "actor": "santiago",
    }, headers=headers)
    assert created.status_code == 200, created.text

    first = test_client.post("/api/v1/orchestration/schedules/tick",
                             json={"actor": "cron"}, headers=headers).json()["data"]
    assert first["processed"] == 1
    assert first["results"][0]["result"] == "queued"

    # a second tick inside the interval must not duplicate the run
    second = test_client.post("/api/v1/orchestration/schedules/tick",
                              json={"actor": "cron"}, headers=headers).json()["data"]
    assert second["processed"] == 0

    listing = test_client.get("/api/v1/orchestration/schedules",
                              headers=headers).json()["data"]
    assert listing[0]["last_job_id"]
    assert listing[0]["due"] is False
    jobs = test_client.get("/api/v1/orchestration/jobs", headers=headers).json()
    assert jobs["total"] == 1


def test_denied_schedule_advances_without_queuing(sched_client):
    test_client, headers, _other = sched_client
    _setup(test_client, headers, grant=False)
    test_client.post("/api/v1/orchestration/schedules", json={
        "name": "unauthorized", "scanner": "trivy",
        "capability": "vulnerability_analysis", "principal": "ci",
        "targets": [{"type": "repository", "value": "acme/forbidden"}],
        "environment": "ci", "interval_minutes": 30, "actor": "santiago",
    }, headers=headers)
    tick = test_client.post("/api/v1/orchestration/schedules/tick",
                            json={"actor": "cron"}, headers=headers).json()["data"]
    assert tick["results"][0]["result"] == "denied"
    assert "no active grant" in tick["results"][0]["reason"]
    jobs = test_client.get("/api/v1/orchestration/jobs", headers=headers).json()
    assert jobs["total"] == 0
    schedule = test_client.get("/api/v1/orchestration/schedules",
                               headers=headers).json()["data"][0]
    assert schedule["last_error"].startswith("denied:")
    assert schedule["due"] is False


def test_schedule_validation_and_isolation(sched_client):
    test_client, headers, other_headers = sched_client
    _setup(test_client, headers)
    mismatch = test_client.post("/api/v1/orchestration/schedules", json={
        "name": "bad", "scanner": "trivy", "capability": "intrusive_testing",
        "principal": "ci", "targets": [{"type": "repository", "value": "x/y"}],
        "actor": "santiago"}, headers=headers)
    assert mismatch.status_code == 422
    duplicate = test_client.post("/api/v1/orchestration/schedules", json={
        "name": "nightly", "scanner": "trivy",
        "capability": "vulnerability_analysis", "principal": "ci",
        "targets": [{"type": "repository", "value": "acme/saria"}],
        "actor": "santiago"}, headers=headers)
    assert duplicate.status_code == 200
    conflict = test_client.post("/api/v1/orchestration/schedules", json={
        "name": "nightly", "scanner": "trivy",
        "capability": "vulnerability_analysis", "principal": "ci",
        "targets": [{"type": "repository", "value": "acme/saria"}],
        "actor": "santiago"}, headers=headers)
    assert conflict.status_code == 409

    assert test_client.get("/api/v1/orchestration/schedules",
                           headers=other_headers).json()["total"] == 0
    schedule_id = test_client.get("/api/v1/orchestration/schedules",
                                  headers=headers).json()["data"][0]["id"]
    assert test_client.patch(f"/api/v1/orchestration/schedules/{schedule_id}",
                             json={"enabled": False, "actor": "santiago"},
                             headers=other_headers).status_code == 404


def test_html_report_escapes_and_includes_evidence(sched_client):
    test_client, headers, _other = sched_client
    engagement = test_client.post("/api/v1/pentest/engagements", json={
        "name": "Q4 <script>alert(1)</script>", "lead": "santiago",
        "methodology": "OWASP WSTG", "actor": "santiago"}, headers=headers).json()["data"]
    test_client.post(f"/api/v1/pentest/engagements/{engagement['id']}/findings", json={
        "title": "Stored <b>XSS</b>", "severity": "HIGH",
        "target": "https://app.example.dev/search?q=<script>",
        "request_evidence": "GET /search?q=<script>alert(1)</script>",
        "response_evidence": "HTTP/1.1 200 OK\n<script>alert(1)</script>",
        "remediation": "escape output", "actor": "santiago"}, headers=headers)

    response = test_client.get(
        f"/api/v1/pentest/engagements/{engagement['id']}/report.html",
        headers=headers)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    body = response.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body
    assert "<script>alert(1)</script>" not in body
    assert "Stored &lt;b&gt;XSS&lt;/b&gt;" in body
    assert "GET /search?q=" in body
    assert "Findings:</strong> 1" in body
    assert "not remediation" in body  # the honesty footnote is present

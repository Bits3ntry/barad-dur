"""SARIF ingest: repeated sightings in one run must not abort the transaction.

A real opengrep run reports many results on the same rule+path; the ingest loop
adds one occurrence per sighting and the dedupe query cannot see rows queued
earlier in the same transaction (the session runs with autoflush=False), so the
second identical sighting hit uq_occurrence_sighting and the whole request
answered 500.
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


def _result(rule, path, line):
    return {
        "ruleId": rule, "level": "warning",
        "message": {"text": f"issue {rule} at {line}"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": path},
            "region": {"startLine": line}}}],
    }


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/sarif-dupes.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "sarif")
    project = models.Project(org_id=org.id, slug="app", name="app")
    session.add(project)
    session.flush()
    session.add(models.ProjectVersion(project_id=project.id, version="1.0"))
    session.commit()
    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}, session


def test_repeated_sightings_are_idempotent(client):
    http, headers, session = client
    run = {
        "tool": {"driver": {"name": "opengrep", "rules": []}},
        "results": [
            _result("js.path-join", "app/page.tsx", 12),
            _result("js.path-join", "app/page.tsx", 12),   # same line, same rule
            _result("js.path-join", "app/page.tsx", 40),
            _result("js.path-join", "app/page.tsx", None),  # no region at all
            _result("js.path-join", "app/page.tsx", None),
        ],
    }
    response = http.post("/api/v1/sarif?project=app&version=1.0",
                         json={"run": run, "actor": "opengrep"}, headers=headers)
    assert response.status_code == 200, response.text
    counts = response.json()["counts"]
    assert counts["received"] == 5

    occurrences = session.query(models.Occurrence).all()
    # line 12 once, line 40 once, the line-less pair once
    assert len(occurrences) == 3
    keys = {row.sighting_key for row in occurrences}
    assert len(keys) == 3


def test_second_ingest_of_same_run_adds_nothing(client):
    http, headers, session = client
    run = {"tool": {"driver": {"name": "opengrep", "rules": []}},
           "results": [_result("js.path-join", "app/page.tsx", 12)]}
    url = "/api/v1/sarif?project=app&version=1.0"
    assert http.post(url, json={"run": run}, headers=headers).status_code == 200
    assert http.post(url, json={"run": run}, headers=headers).status_code == 200
    assert session.query(models.Occurrence).count() == 1
    assert session.query(models.Finding).count() == 1

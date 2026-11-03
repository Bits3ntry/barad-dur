"""Exposure flow: the numbers the Sankey draws must add up.

The diagram is only honest if the stages are consistent — sources sum to
received, priority buckets sum to actionable, outcomes are counted from the same
rows — so those invariants are asserted against real rows, not eyeballed.
"""
import datetime
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
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/flow.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "k")
    project = models.Project(org_id=org.id, slug="api", name="api")
    session.add(project)
    session.flush()
    now = models.utcnow()

    counter = {"n": 0}

    def finding(kind, tool, priority, status="open", sla=None, first_seen=None):
        counter["n"] += 1
        session.add(models.Finding(
            org_id=org.id, project_id=project.id, kind=kind, tool=tool, source="api",
            severity="HIGH", priority=priority, status=status,
            title=f"{kind} {tool}",
            fingerprint=f"{kind}-{tool}-{priority}-{status}-{counter['n']}",
            first_seen_at=first_seen or now, last_seen_at=now,
            sla_deadline=sla, created_at=now, updated_at=now))

    # Three engines spelling themselves differently, plus one stale finding.
    finding("code-weakness", "OpenGrep", "P0")
    finding("code-weakness", "opengrep", "P1")
    finding("code-weakness", "Opengrep OSS", "P1")
    finding("vulnerability", "osv", "P3")
    finding("vulnerability", "osv", "P2", status="suppressed")
    finding("vulnerability", "osv", "P0",
            sla=now - datetime.timedelta(days=2))
    finding("vulnerability", "osv", "P1",
            first_seen=now - datetime.timedelta(days=90))
    session.commit()
    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}


def test_stages_add_up(client):
    http, headers = client
    data = http.get("/api/v1/dashboard/exposure-flow?window=30", headers=headers).json()["data"]

    assert sum(row["count"] for row in data["sources"]) == data["received"]
    assert data["received"] == 6  # the 90-day-old finding is outside the window
    assert sum(data["by_priority"].values()) == data["actionable"]
    assert data["actionable"] == 6  # suppressed is not actionable
    assert data["outcomes"]["open"] == 6
    assert data["outcomes"]["suppressed"] == 1
    assert data["outcomes"]["past_sla"] == 1


def test_opengrep_spellings_collapse_to_one_source(client):
    http, headers = client
    data = http.get("/api/v1/dashboard/exposure-flow?window=30", headers=headers).json()["data"]
    code = [row for row in data["sources"] if row["kind"] == "code-weakness"]
    assert len(code) == 1
    assert code[0]["tool"] == "opengrep"
    assert code[0]["count"] == 3


def test_unknown_scope_is_404_not_org_wide(client):
    http, headers = client
    assert http.get("/api/v1/dashboard/exposure-flow?project=does-not-exist",
                    headers=headers).status_code == 404
    assert http.get("/api/v1/dashboard/exposure-flow?project=api&version=nope",
                    headers=headers).status_code == 404


def test_project_scope_keeps_only_that_project(client):
    http, headers = client
    data = http.get("/api/v1/dashboard/exposure-flow?project=api",
                    headers=headers).json()["data"]
    assert data["received"] == 6

"""CTEM cycle: a phase is only 'done' when its own table says so.

The failure mode worth guarding is a phase reporting healthy because the data it
would be judged on is missing.
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
def context(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/ctem.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "k")
    session.commit()
    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}, session, org


def _phases(http, headers):
    data = http.get("/api/v1/ctem/overview", headers=headers).json()["data"]
    return {phase["key"]: phase for phase in data["phases"]}


def test_empty_org_reports_nothing_done(context):
    http, headers, _session, _org = context
    phases = _phases(http, headers)
    assert set(phases) == {"scoping", "discovery", "prioritization",
                           "validation", "mobilization"}
    assert all(phase["status"] == "empty" for phase in phases.values())
    assert all(phase["progress"] == 0 for phase in phases.values())


def test_scoping_needs_projects_versions_and_scope_targets(context):
    http, headers, session, org = context
    project = models.Project(org_id=org.id, slug="api", name="api")
    session.add(project)
    session.flush()
    session.add(models.ProjectVersion(project_id=project.id, version="1.0"))
    session.commit()

    phases = _phases(http, headers)
    # a project with a version but no declared scope is partial, not done
    assert phases["scoping"]["status"] == "partial"

    session.add(models.ScopeTarget(org_id=org.id, target_type="repository",
                                   value="api", status="active"))
    session.commit()
    assert _phases(http, headers)["scoping"]["status"] == "done"


def test_discovery_needs_components_not_just_projects(context):
    http, headers, session, org = context
    project = models.Project(org_id=org.id, slug="api", name="api")
    session.add(project)
    session.flush()
    session.add(models.ProjectVersion(project_id=project.id, version="1.0"))
    session.commit()
    assert _phases(http, headers)["discovery"]["status"] == "empty"

    session.add(models.Component(org_id=org.id, name="requests",
                                 version="2.0", identity_key="requests@2.0"))
    session.commit()
    assert _phases(http, headers)["discovery"]["status"] in {"partial", "done"}


def test_prioritization_requires_every_open_finding_ranked(context):
    http, headers, session, org = context
    project = models.Project(org_id=org.id, slug="api", name="api")
    session.add(project)
    session.flush()
    now = models.utcnow()

    def finding(priority):
        session.add(models.Finding(
            org_id=org.id, project_id=project.id, kind="vulnerability",
            source="api", title="t", severity="HIGH", status="open",
            priority=priority, fingerprint=f"fp-{priority or 'none'}",
            first_seen_at=now, last_seen_at=now, created_at=now, updated_at=now))

    finding("P1")
    session.commit()
    assert _phases(http, headers)["prioritization"]["status"] == "done"

    finding(None)
    session.commit()
    assert _phases(http, headers)["prioritization"]["status"] == "partial"

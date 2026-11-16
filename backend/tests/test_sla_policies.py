"""SLA policies: a policy that can be created, edited, and applied to what exists.

Two dead ends this covers, both found by asking "is there an SLA defined?":

- With zero policies the console rendered no editor, so a fresh organisation
  could never write the first one.
- Editing a policy posted the same name again and got a 409, which looked like
  "already there" while the days never moved.

The deadline is derived (`created_at` + bucket), so an edit has to recompute the
findings that already exist — otherwise the policy says 30 days next to findings
computed from 90.
"""
import datetime
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models  # noqa: E402
from backend.app.auth_local import ensure_aware  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/sla.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="org", name="Org")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "sla")
    session.commit()
    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}, session, org


def _finding(session, org, priority):
    finding = models.Finding(
        org_id=org.id, title=f"{priority} thing", severity="high", kind="vulnerability",
        fingerprint=f"fp-{priority}", source="test", priority=priority,
        created_at=models.utcnow() - datetime.timedelta(days=10),
        updated_at=models.utcnow())
    session.add(finding)
    session.commit()
    return finding


def test_a_fresh_org_has_no_policy_and_no_deadline(env):
    client, headers, session, org = env
    finding = _finding(session, org, "P1")
    assert client.get("/api/v1/sla/policies", headers=headers).json()["data"] == []
    assert session.get(models.Finding, finding.id).sla_deadline is None


def test_creating_the_first_policy_lands_deadlines_on_existing_findings(env):
    client, headers, session, org = env
    finding = _finding(session, org, "P1")
    created = client.post("/api/v1/sla/policies", headers=headers, json={
        "name": "Standard", "p0_days": 7, "p1_days": 30, "p2_days": 90,
        "p3_days": 180, "make_default": True})
    assert created.status_code == 200, created.text

    session.expire_all()
    deadline = session.get(models.Finding, finding.id).sla_deadline
    assert deadline is not None
    # Ten days old + a 30-day bucket: the deadline is twenty days away, not "now".
    left = (ensure_aware(deadline) - models.utcnow()).days
    assert 19 <= left <= 20


def test_editing_the_days_recomputes_instead_of_409(env):
    client, headers, session, org = env
    finding = _finding(session, org, "P2")
    first = client.post("/api/v1/sla/policies", headers=headers, json={
        "name": "Standard", "p0_days": 7, "p1_days": 30, "p2_days": 90,
        "p3_days": 180, "make_default": True}).json()["data"]

    patched = client.patch(f"/api/v1/sla/policies/{first['id']}", headers=headers,
                           json={"p2_days": 14, "actor": "tester"})
    assert patched.status_code == 200, patched.text
    assert patched.json()["data"]["p2_days"] == 14
    session.expire_all()
    stored = session.get(models.Finding, finding.id).sla_deadline
    left = (ensure_aware(stored) - models.utcnow()).days
    assert left <= 4, "the new bucket has to reach findings that already exist"


def test_only_one_policy_is_default(env):
    client, headers, _, _ = env
    first = client.post("/api/v1/sla/policies", headers=headers, json={
        "name": "Standard", "p0_days": 7, "p1_days": 30, "p2_days": 90,
        "p3_days": 180, "make_default": True}).json()["data"]
    client.post("/api/v1/sla/policies", headers=headers, json={
        "name": "Strict", "p0_days": 1, "p1_days": 7, "p2_days": 30,
        "p3_days": 90, "make_default": True})
    rows = client.get("/api/v1/sla/policies", headers=headers).json()["data"]
    assert sum(1 for row in rows if row["is_default"]) == 1
    assert next(row for row in rows if row["is_default"])["name"] == "Strict"
    # …and the old one keeps its id so an edit still targets the same row.
    assert any(row["id"] == first["id"] and not row["is_default"] for row in rows)

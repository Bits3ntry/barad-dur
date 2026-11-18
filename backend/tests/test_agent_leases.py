"""The lease, atomically: claim → expire → back to the queue, or failed and closed.

Three facts, each one a failure that happened on a live estate:

* a lane that claims a task and dies leaves it `claimed` for ever, because the queue
  lists `queued` only — so nobody else ever sees it;
* after the third release the task is evidence about the task, not about the queue,
  and it must fail **with the reason** instead of looping;
* a mission whose tasks are all terminal is not `running` any more — leaving it
  running is the screen lying.

No HTTP, no model, no network: the reaper is a pure function over rows.
"""
import datetime
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402
from backend.app.routers.agent import (  # noqa: E402
    MAX_ATTEMPTS, BudgetIn, _release_expired_leases)


@pytest.fixture()
def session(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/leases.db")
    monkeypatch.setenv("BOOTSTRAP_TOKEN", "boot")
    create_app()
    db = session_factory()()
    models.Base.metadata.create_all(db.get_bind())
    yield db
    db.close()


def _mission_with_task(db, *, status="claimed", attempts=1, minutes_ago=30):
    org = models.Organization(slug="o", name="Org")
    db.add(org)
    db.flush()
    mission = models.AgentMission(
        org_id=org.id, actor="ana", actor_role="analyst",
        goal="validate the search endpoint", capability="validate",
        profile="angmar", status="running", targets="[]", tools='["curl"]',
        budget='{"steps": 10, "tokens": 60000}')
    db.add(mission)
    db.flush()
    task = models.AgentTask(
        org_id=org.id, mission_id=mission.id, kind="validate.finding",
        target='{"value": "https://lab.example/"}', tools='["curl"]',
        must_return='["verdict"]', status=status, attempts=attempts,
        worker="lane-1", token_hash="deadbeef" if status == "claimed" else None,
        lease_expires_at=models.utcnow() - datetime.timedelta(minutes=minutes_ago))
    db.add(task)
    db.commit()
    return org, mission, task


def test_an_expired_lease_goes_back_to_the_queue(session):
    org, mission, task = _mission_with_task(session, attempts=1)

    released = _release_expired_leases(session, org.id)

    assert released == 1
    session.refresh(task)
    assert task.status == "queued"
    assert task.worker is None
    assert task.lease_expires_at is None
    # The token dies with the lease: another worker claims with a new one.
    assert task.token_hash is None
    # Still work to do, so the mission is still running.
    session.refresh(mission)
    assert mission.status == "running"


def test_the_third_release_fails_the_task_and_closes_the_mission(session):
    org, mission, task = _mission_with_task(session, attempts=MAX_ATTEMPTS)

    _release_expired_leases(session, org.id)

    session.refresh(task)
    assert task.status == "failed"
    assert task.error and "lease expired" in task.error
    assert task.finished_at is not None
    # A mission with nothing open is history, not a spinner.
    session.refresh(mission)
    assert mission.status == "failed"
    assert mission.finished_at is not None


def test_a_live_lease_is_left_alone(session):
    org, mission, task = _mission_with_task(session, attempts=1, minutes_ago=-5)

    assert _release_expired_leases(session, org.id) == 0

    session.refresh(task)
    assert task.status == "claimed"
    assert task.worker == "lane-1"


def test_the_default_budget_funds_the_default_run():
    """A ceiling below what the default step count spends is a trap.

    A validate completion costs ~2.5–3k tokens (tool schema + envelope + brief);
    the live runs spent 22–28k over ten steps and were refused at the eighth — after
    doing the work. This is the guard so nobody lowers the default again silently.
    """
    budget = BudgetIn()
    assert budget.tokens >= budget.steps * 3000


def test_an_origin_covers_its_paths_but_not_another_host():
    """The envelope normalises a URL to its origin, so a path task must fit inside it.

    Comparing the two strings refused a task for being inside the envelope it was
    created from (`422 … not in the mission envelope`), which is how a mission that
    looked approved never got anything to run.
    """
    from backend.app.routers.agent import _covered_by

    assert _covered_by("http://juice-shop.demo", "http://juice-shop.demo/rest/a?q=1")
    assert _covered_by("https://lab.example/", "https://lab.example/x")
    assert not _covered_by("http://juice-shop.demo", "http://otro.example/x")
    assert not _covered_by("http://juice-shop.demo", "https://juice-shop.demo/x")

"""Concurrency limits are policy the operator owns, not constants in the code.

Two of them wait at the claim (per zone, per organization) and one refuses at the
door (queue ceiling). The distinction is the whole point: a cap that turns a run
into `failed` teaches the operator to read their own limits as a bug.
"""
import json
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models, surface_runtime  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/runtime.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "runtime")
    session.commit()
    from fastapi.testclient import TestClient

    return TestClient(app), {"X-API-Key": key}, session, org


def _job(session, org, *, value, status="queued", job_id=None):
    job = models.ScanJob(
        id=job_id or models.uuid_hex(), org_id=org.id, scanner="shauron-surface",
        capability="passive_discovery", principal="collector",
        targets=json.dumps([{"type": "domain", "value": value}]),
        profile=json.dumps({"name": "recon.simple", "level": "simple"}),
        status=status, origin="cloud", executor="shauron",
        tasks="[]", ticket_json="{}")
    session.add(job)
    session.commit()
    return job


# ── the policy itself ────────────────────────────────────────────────────────

def test_limits_have_defaults_until_somebody_changes_them(env):
    _client, _headers, session, _org = env
    assert surface_runtime.policy(session) == surface_runtime.DEFAULTS


def test_a_partial_row_still_answers_every_limit(env):
    _client, _headers, session, _org = env
    session.add(models.PlatformSetting(
        name="surface_runtime", value=json.dumps({"per_zone": 3})))
    session.commit()
    limits = surface_runtime.policy(session)
    assert limits["per_zone"] == 3
    assert limits["per_org"] == surface_runtime.DEFAULTS["per_org"]


def test_a_limit_outside_its_bounds_is_refused_with_the_reason(env):
    _client, _headers, session, org = env
    with pytest.raises(ValueError) as error:
        surface_runtime.save(session, {"per_zone": 40}, "tester", org.id)
    assert "per_zone must be between 1 and 8" in str(error.value)


def test_a_change_is_audited_with_what_moved(env):
    _client, _headers, session, org = env
    surface_runtime.save(session, {"per_zone": 3, "per_org": 4,
                                   "per_worker": 1, "queue_ceiling": 500},
                         "owner@example.com", org.id)
    entry = (session.query(models.AuditLog)
             .filter_by(action="surface.runtime_limits").one())
    assert "per_zone 2 -> 3" in (entry.detail or "")
    assert entry.actor == "owner@example.com"


# ── where it is enforced ─────────────────────────────────────────────────────

def test_subdomains_of_one_domain_share_a_zone():
    one = surface_runtime.zone_of_targets([{"type": "domain", "value": "api.councilbox.com"}])
    two = surface_runtime.zone_of_targets([{"type": "domain", "value": "dev.api.councilbox.com"}])
    root = surface_runtime.zone_of_targets([{"type": "domain", "value": "councilbox.com"}])
    assert one == two == root == "councilbox.com"


def test_an_unrelated_domain_is_its_own_zone():
    assert (surface_runtime.zone_of_targets([{"type": "domain", "value": "bitsentry.xyz"}])
            != surface_runtime.zone_of_targets([{"type": "domain", "value": "councilbox.com"}]))


def test_the_zone_cap_holds_a_run_at_the_claim_instead_of_failing_it(env):
    _client, _headers, session, org = env
    surface_runtime.save(session, {"per_zone": 1, "per_org": 8,
                                   "per_worker": 1, "queue_ceiling": 500},
                         "tester", org.id)
    _job(session, org, value="api.councilbox.com", status="running")
    allowed, why = surface_runtime.capacity(
        session, org.id, [{"type": "domain", "value": "dev.councilbox.com"}])
    assert allowed is False
    assert "zone full" in why and "councilbox.com" in why


def test_a_different_zone_is_not_blocked_by_a_busy_one(env):
    _client, _headers, session, org = env
    surface_runtime.save(session, {"per_zone": 1, "per_org": 8,
                                   "per_worker": 1, "queue_ceiling": 500},
                         "tester", org.id)
    _job(session, org, value="api.councilbox.com", status="running")
    allowed, _why = surface_runtime.capacity(
        session, org.id, [{"type": "domain", "value": "bitsentry.xyz"}])
    assert allowed is True


def test_the_org_cap_binds_before_the_zone_cap_does(env):
    _client, _headers, session, org = env
    surface_runtime.save(session, {"per_zone": 4, "per_org": 1,
                                   "per_worker": 1, "queue_ceiling": 500},
                         "tester", org.id)
    _job(session, org, value="api.councilbox.com", status="running")
    allowed, why = surface_runtime.capacity(
        session, org.id, [{"type": "domain", "value": "bitsentry.xyz"}])
    assert allowed is False and "organization full" in why


def test_the_ceiling_refuses_a_new_run_but_leaves_the_queue_alone(env):
    _client, _headers, session, org = env
    surface_runtime.save(session, {"per_zone": 2, "per_org": 4,
                                   "per_worker": 1, "queue_ceiling": 50},
                         "tester", org.id)
    for index in range(50):
        _job(session, org, value=f"host{index}.example")
    admitted, why = surface_runtime.admission(
        session, org.id, [{"type": "domain", "value": "new.example"}])
    assert admitted is False
    assert "queue ceiling reached (50/50)" in why
    assert (session.query(models.ScanJob).filter_by(status="queued").count() == 50)


# ── the screen ───────────────────────────────────────────────────────────────

def test_the_screen_gets_the_limits_and_the_state_they_act_on(env):
    client, headers, session, org = env
    _job(session, org, value="api.councilbox.com", status="running")
    _job(session, org, value="dev.councilbox.com")
    body = client.get("/api/v1/surface/runtime", headers=headers).json()
    assert body["policy"]["per_zone"] == surface_runtime.DEFAULTS["per_zone"]
    assert body["state"]["in_flight"] == 1
    assert body["state"]["queue"] == 1
    assert body["state"]["per_zone"]["councilbox.com"] == 1
    assert body["bounds"]["per_zone"] == [1, 8]


def test_the_screen_says_why_a_run_is_waiting(env):
    client, headers, session, org = env
    _job(session, org, value="api.councilbox.com", status="running")
    _job(session, org, value="dev.councilbox.com", status="running")
    _job(session, org, value="new.councilbox.com")
    body = client.get("/api/v1/surface/runtime", headers=headers).json()
    waiting = body["state"]["waiting"]
    assert waiting and waiting[0]["zone"] == "councilbox.com"
    assert "zone full: 2 in flight" in waiting[0]["reason"]


def test_updating_the_limits_returns_the_new_policy(env):
    client, headers, _session, _org = env
    response = client.put("/api/v1/surface/runtime",
                          json={"per_zone": 3, "per_org": 6, "per_worker": 1,
                                "queue_ceiling": 800, "actor": "owner@example.com"},
                          headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["policy"]["per_zone"] == 3
    assert response.json()["policy"]["queue_ceiling"] == 800


def test_an_out_of_bounds_update_is_a_422_with_the_reason(env):
    client, headers, _session, _org = env
    response = client.put("/api/v1/surface/runtime",
                          json={"per_zone": 99, "per_org": 6, "per_worker": 1,
                                "queue_ceiling": 800, "actor": "owner@example.com"},
                          headers=headers)
    assert response.status_code == 422


# ── the pool: never empty, wider under load ──────────────────────────────────

def test_the_pool_is_never_empty_even_with_an_idle_queue(env):
    _client, _headers, session, org = env
    pool = surface_runtime.desired_workers(session, org.id)
    assert pool["target"] == 1
    assert pool["binding"] == "min_workers"


def test_the_pool_grows_with_the_backlog_and_stops_at_the_ceiling(env):
    _client, _headers, session, org = env
    surface_runtime.save(session, {"per_zone": 2, "per_org": 32, "per_worker": 1,
                                   "queue_ceiling": 5000, "min_workers": 1,
                                   "max_workers": 4, "scale_down_after_s": 600},
                         "tester", org.id)
    for index in range(3):
        _job(session, org, value=f"a{index}.example")
    assert surface_runtime.desired_workers(session, org.id)["target"] == 3
    for index in range(9):
        _job(session, org, value=f"b{index}.example")
    pool = surface_runtime.desired_workers(session, org.id)
    assert pool["target"] == 4 and pool["binding"] == "max_workers"


def test_runs_in_flight_count_toward_the_pool(env):
    _client, _headers, session, org = env
    surface_runtime.save(session, {"per_zone": 2, "per_org": 32, "per_worker": 2,
                                   "queue_ceiling": 5000, "min_workers": 1,
                                   "max_workers": 8, "scale_down_after_s": 600},
                         "tester", org.id)
    _job(session, org, value="a.example", status="running")
    _job(session, org, value="b.example", status="running")
    _job(session, org, value="c.example")
    # 3 runs, 2 per worker -> 2 workers, not 1: a pool sized only on the queue
    # would shrink while it is still working.
    assert surface_runtime.desired_workers(session, org.id)["target"] == 2


def test_the_screen_publishes_the_pool_target(env):
    client, headers, session, org = env
    _job(session, org, value="a.example")
    body = client.get("/api/v1/surface/runtime", headers=headers).json()
    assert body["state"]["pool"]["target"] == 1
    assert body["policy"]["min_workers"] == 1

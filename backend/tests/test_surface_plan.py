"""A surface plan says what will run, why it will not, and what came back.

The plan is the only place that composes a scan: the CLI never chooses a tool,
the modal lists profiles, and the engine's verdict per capability decides whether
a step is `allow`, `not_authorized`, `not_accepted` or `not_installed`. A run is
then a frozen plan plus the steps the executor reports, which is what makes the
timeline identical for the laptop and the worker.
"""
import datetime
import json
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import authorization, models, surface_plan  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/surface.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "surface")
    session.add(models.ScopeExclusion(
        org_id=org.id, target_type="domain", value="thirdparty.example",
        reason="a supplier's box"))
    session.commit()
    from fastapi.testclient import TestClient

    return TestClient(app), {"X-API-Key": key}, session, org


def _grant(session, org, values, capabilities="passive_discovery,active_verification",
           status="active", target_type="domain",
           principal=authorization.COLLECTOR_PRINCIPAL):
    grant = models.ScanGrant(
        org_id=org.id, principal=principal,
        capabilities=capabilities, status=status, justification="test",
        issued_by="tester", policy_version=1, level="simple", source="manual",
        valid_from=models.utcnow(),
        valid_until=models.utcnow() + datetime.timedelta(days=30))
    session.add(grant)
    session.flush()
    for value in values:
        grant.targets.append(models.ScanGrantTarget(
            grant_id=grant.id, target_type=target_type, target_value=value))
    session.commit()
    return grant


TARGET = {"type": "domain", "value": "api.example.com"}
WEB_TARGET = {"type": "domain", "value": "api.example.com"}


def test_catalog_lists_profiles_and_which_planes_can_run_them(env):
    client, headers, _session, _org = env
    body = client.get("/api/v1/surface/catalog", params={"plane": "cli"},
                      headers=headers).json()
    by_name = {row["name"]: row for row in body["profiles"]}
    assert by_name["recon.simple"]["runnable_here"] is True
    assert by_name["web.redteam"]["runnable_here"] is False
    # Two web scans: the basic one, and the deep one. A third tier would be a
    # third choice the operator has to understand for no extra answer.
    assert "recon.advanced" not in by_name
    # Deep recon is a profile, and it is cloud-only: the laptop never gets it.
    assert by_name["web.redteam"]["plane"] == ["cloud"]
    assert body["tools_total"] >= 18


def test_a_plan_without_a_grant_names_the_capability_that_is_missing(env):
    """The worker path: the engine decides, and the reason is the engine's."""
    _client, _headers, session, org = env
    plan = surface_plan.resolve(session, org, "recon.simple", [TARGET],
                                check_grants=True)
    steps = [step for stage in plan["stages"] for step in stage["steps"]]
    assert {step["state"] for step in steps} == {"not_authorized"}
    # DNS, TLS, a header read and a technology fingerprint: recon never asks for
    # a vulnerability engine, so every one of them sits inside `simple`.
    assert surface_plan.states(plan) == {"not_authorized": 4}
    assert steps[0]["reason"]


def test_an_active_grant_turns_the_same_plan_into_allowed_steps(env):
    _client, _headers, session, org = env
    _grant(session, org, ["api.example.com", "*.api.example.com"])
    plan = surface_plan.resolve(session, org, "recon.simple", [TARGET],
                                check_grants=True)
    steps = [step for stage in plan["stages"] for step in stage["steps"]]
    assert {step["state"] for step in steps} == {"allow"}
    assert plan["basis"] == "grant"
    assert [step["tool"] for step in steps] == ["dns", "tls", "http-head", "whatweb"]


def test_the_cli_caller_needs_no_grant_and_the_plan_says_so(env):
    """An owner at a terminal is not the collector: the basis is recorded."""
    client, headers, _session, _org = env
    plan = client.post("/api/v1/surface/plan",
                       json={"profile": "recon.simple", "targets": [TARGET],
                             "plane": "cli"}, headers=headers).json()["plan"]
    steps = [step for stage in plan["stages"] for step in stage["steps"]]
    assert {step["state"] for step in steps} == {"allow"}
    assert plan["basis"] == "admin_override"


def test_an_exclusion_blocks_the_plan_and_no_run_is_created(env):
    client, headers, _session, _org = env
    target = {"type": "domain", "value": "thirdparty.example"}
    plan = client.post("/api/v1/surface/plan",
                       json={"profile": "recon.simple", "targets": [target]},
                       headers=headers).json()["plan"]
    assert plan["blocked_targets"][0]["value"] == "thirdparty.example"
    assert all(step["state"] == "excluded"
               for stage in plan["stages"] for step in stage["steps"])
    response = client.post("/api/v1/surface/runs",
                           json={"profile": "recon.simple", "targets": [target]},
                           headers=headers)
    assert response.status_code == 409
    assert "excluded" in response.json()["detail"]


def test_redteam_is_refused_on_the_cli_plane_without_blaming_the_grant(env):
    client, headers, _session, _org = env
    body = client.post("/api/v1/surface/plan",
                       json={"profile": "web.redteam", "targets": [TARGET]},
                       headers=headers).json()
    assert body["plan"]["refused"] is True
    assert "Barad-dûr" in body["verdict"]
    assert "grant" not in body["verdict"].lower()
    response = client.post("/api/v1/surface/runs",
                           json={"profile": "web.redteam", "targets": [TARGET]},
                           headers=headers)
    assert response.status_code == 409


def test_disabled_tools_are_refused_by_policy_not_by_absence(env):
    client, headers, session, _org = env
    session.add(models.PlatformSetting(
        name="surface_policy", value='{"disabled": ["tls"]}'))
    session.commit()
    body = client.post("/api/v1/surface/plan",
                       json={"profile": "recon.simple", "targets": [TARGET]},
                       headers=headers).json()
    states = {step["tool"]: step["state"]
              for stage in body["plan"]["stages"] for step in stage["steps"]}
    assert states["tls"] == "not_accepted"
    assert states["dns"] == "allow"


def test_a_run_records_steps_once_and_keeps_the_timeline(env):
    client, headers, _session, _org = env
    started = client.post("/api/v1/surface/runs",
                          json={"profile": "recon.simple", "targets": [TARGET],
                                "engagement": "acme-q4"}, headers=headers)
    assert started.status_code == 201, started.text
    run_id = started.json()["run_id"]

    steps = [{"step": "discover.dns", "stage": "discover", "tool": "dns",
              "status": "ok", "items_in": 1, "items_out": 1,
              "counters": {"ipv4": 2}, "coverage": "full",
              "artifacts": [{"path": "raw/discover.dns.json", "sha256": "ab"}]},
             {"step": "probe.nmap", "stage": "probe", "tool": "nmap",
              "status": "dropped", "reason": "worker has no NET_RAW",
              "coverage": "unknown"}]
    first = client.post(f"/api/v1/surface/runs/{run_id}/steps",
                        json={"steps": steps}, headers=headers)
    assert first.json() == {"run_id": run_id, "accepted": 2, "skipped": 0}
    again = client.post(f"/api/v1/surface/runs/{run_id}/steps",
                        json={"steps": steps}, headers=headers)
    assert again.json()["accepted"] == 0
    assert again.json()["skipped"] == 2

    finished = client.post(f"/api/v1/surface/runs/{run_id}/finish",
                           json={"ok": True, "manifest": {
                               "profile": "recon.simple", "coverage": "partial",
                               "observations": 5, "duration_s": 4.2,
                               "counters": {"steps": 3, "ok": 2, "dropped": 1,
                                            "failed": 0},
                               "artifacts": [{"path": "raw/x.json"}]}},
                           headers=headers)
    assert finished.json()["status"] == "finished"

    flow = client.get(f"/api/v1/surface/runs/{run_id}", headers=headers).json()
    assert flow["run"]["evidence_state"] == "complete"
    assert flow["summary"]["observations"] == 5
    assert [step["step"] for step in flow["steps"]].count("discover.dns") == 1
    assert flow["verdict"].startswith("2 step(s) ok")
    kinds = [event["kind"] for event in flow["events"]]
    assert kinds[0] == "accepted"
    assert "step" in kinds and "finished" in kinds
    # The plan arrives with the run so the trace can explain a skipped step.
    assert flow["plan"]["profile"] == "recon.simple"
    assert flow["run"]["authorization"]["engagement"] == "acme-q4"


def test_a_worker_token_cannot_plan_a_cli_run(env):
    """Only a human owner/admin runs the CLI; a worker is sent to the platform."""
    client, _headers, session, org = env
    from backend.app import auth
    worker = models.Worker(org_id=org.id, name="w1", status="online")
    session.add(worker)
    session.flush()
    raw = "worker-token-for-test"
    session.add(models.WorkerToken(org_id=org.id, worker_id=worker.id,
                                   token_hash=auth.key_hash(raw), label="t"))
    session.commit()
    response = client.post("/api/v1/surface/plan",
                           json={"profile": "recon.simple", "targets": [TARGET]},
                           headers={"X-Worker-Token": raw})
    assert response.status_code == 403


def test_no_profile_hunts_a_vulnerability():
    """This plane is reconnaissance. A certificate, a header, a version, a path:
    facts about what stands there. The moment a profile ships an engine that
    looks for weaknesses, the product changed category without anyone deciding it.
    """
    document = surface_plan.catalog()
    tools = document["tools"]
    hunters = {"nuclei", "dalfox", "sqlmap", "opengrep", "trivy-fs", "trivy-image"}
    for name, profile in document["profiles"].items():
        # Code and image profiles analyse artefacts, not a host, and keep their
        # engines: this rule is about what a web scan is allowed to be.
        if not name.startswith(("web.", "recon.")):
            continue
        used = {step for stage in profile["stages"] for step in stage["tools"]}
        assert not (used & hunters), f"{name} ships a vulnerability engine: {used & hunters}"
        for tool in used:
            assert tools[tool]["capability"] != "intrusive_testing", f"{name}: {tool}"


def test_a_grant_issued_from_the_console_covers_a_run_the_platform_resolves(env):
    """The console writes `principal=console`; the plan asks as `collector`.

    Comparing those two strings literally made every console-approved grant
    invisible to every cloud scan — the screen said "authorized", the plan said
    "not authorized", and both were reading the same row.
    """
    client, headers, session, org = env
    from backend.app import authorization
    grant = _grant(session, org, ["api.example.com", "*.api.example.com"],
                   principal="console")
    assert grant.principal == "console"
    plan = client.post("/api/v1/surface/plan",
                       json={"profile": "recon.simple", "targets": [TARGET],
                             "plane": "cloud"}, headers=headers).json()["plan"]
    steps = [step for stage in plan["stages"] for step in stage["steps"]]
    assert {step["state"] for step in steps} == {"allow"}, steps[0]
    assert plan["principal"] == authorization.COLLECTOR_PRINCIPAL


def test_the_two_web_tiers_are_the_same_recon_at_two_depths(env):
    """Basic answers 'what is this'. Deep answers the same, better: ports,
    services, versions and paths. Neither one looks for a weakness."""
    client, headers, _session, _org = env
    basic = client.post("/api/v1/surface/plan",
                        json={"profile": "recon.simple", "targets": [TARGET]},
                        headers=headers).json()["plan"]
    deep = client.post("/api/v1/surface/plan",
                       json={"profile": "web.redteam", "targets": [TARGET],
                             "plane": "cloud"}, headers=headers).json()["plan"]

    def tools_of(plan):
        return [step["tool"] for stage in plan["stages"] for step in stage["steps"]]

    basic_tools, deep_tools = tools_of(basic), tools_of(deep)
    assert set(basic_tools) < set(deep_tools), deep_tools
    assert "ffuf-paths" in deep_tools and "ffuf-paths" not in basic_tools
    assert basic["level"] == "simple" and deep["level"] == "redteam"


def test_wpscan_waits_until_something_has_said_wordpress(env):
    """The gate travels from the tool into the step.

    Running wpscan against every domain spends a scan to learn the site is not
    WordPress; the plan carries the condition and the executor honours it after
    reading the fingerprint.
    """
    client, headers, _session, _org = env
    plan = client.post("/api/v1/surface/plan",
                       json={"profile": "web.redteam", "targets": [TARGET],
                             "plane": "cloud"}, headers=headers).json()["plan"]
    steps = {step["tool"]: step for stage in plan["stages"] for step in stage["steps"]}
    assert steps["wp-enum"]["when"] == {"technology": ["wordpress"]}
    # The tools that answer the question without a sign run unguarded.
    assert steps["whatweb"].get("when") is None
    assert steps["nmap"].get("when") is None


def test_the_catalog_shipped_with_the_platform_is_the_one_shauron_publishes():
    """Drift is visible, not silent: the hash in the file is recomputed here."""
    document = surface_plan.catalog()
    assert document["catalog_sha256"] == surface_plan.catalog_hash()
    # Every profile's tools exist, and no redteam tool leaks into a simple profile.
    for profile in document["profiles"].values():
        for stage in profile["stages"]:
            for tool in stage["tools"]:
                assert tool in document["tools"], f"{profile['name']}: {tool}"
                if profile.get("level") == "simple":
                    assert document["tools"][tool].get("level") in (None, "simple")


def test_a_cloud_run_is_held_by_a_worker_not_by_the_laptop(env):
    """`origin`/`executor` are the two columns an operator reads to know who ran
    what. Recording 'cli' for a console-launched run made the console lie."""
    client, headers, _session, _org = env
    started = client.post("/api/v1/surface/runs",
                          json={"profile": "recon.simple", "targets": [TARGET],
                                "plane": "cloud"}, headers=headers)
    assert started.status_code == 201, started.text
    run = client.get(f"/api/v1/surface/runs/{started.json()['run_id']}",
                     headers=headers).json()["run"]
    assert run["origin"] == "cloud"
    assert run["executor"] == "shauron"
    assert run["authorization"]["basis"] == "admin_override"


def test_a_worker_can_claim_an_operator_launched_run(env):
    """The claim path re-validates authorization. An override run has no grant, so
    without honouring the recorded basis every console-launched scan would be
    refused at the first claim — the run would sit queued forever."""
    client, headers, session, org = env
    started = client.post("/api/v1/surface/runs",
                          json={"profile": "recon.simple", "targets": [TARGET],
                                "plane": "cloud"}, headers=headers)
    assert started.status_code == 201, started.text

    # A worker advertises the capabilities it can run; the claim requires the job's
    # set to be a subset of that, because a surface job names every capability its
    # steps need.
    worker = models.Worker(org_id=org.id, name="w-claim", status="online",
                           capabilities='["passive_discovery","active_verification"]',
                           max_concurrent=2)
    session.add(worker)
    session.commit()

    claimed = client.post("/api/v1/orchestration/jobs/claim",
                          json={"worker_id": worker.id, "actor": "w-claim"},
                          headers=headers)
    assert claimed.status_code == 200, claimed.text
    body = claimed.json()
    assert body["data"] is not None, body
    assert body["data"]["id"] == started.json()["run_id"]
    assert body["data"]["status"] == "leased"


def test_the_run_says_what_changed_since_the_previous_one(env):
    """A receipt counts observations; the diff is the sentence an operator needs."""
    from backend.app import surface_diff

    _client, _headers, session, org = env
    first = client_run = models.ScanJob(
        org_id=org.id, scanner="shauron-surface", capability="network",
        principal="tester", status="finished", origin="cloud", executor="shauron",
        targets=json.dumps([{"type": "domain", "value": "api.example.com"}]),
        profile=json.dumps({"name": "recon.simple"}),
        created_at=models.utcnow() - datetime.timedelta(hours=2),
        started_at=models.utcnow() - datetime.timedelta(hours=2),
        finished_at=models.utcnow() - datetime.timedelta(hours=2) + datetime.timedelta(seconds=40))
    session.add(first)
    session.flush()
    asset = models.Asset(org_id=org.id, type="domain", value="api.example.com",
                         source="manual")
    session.add(asset)
    session.flush()
    base = models.utcnow() - datetime.timedelta(hours=2)
    session.add(models.Observation(
        org_id=org.id, asset_id=asset.id, kind="certificate", subject="api.example.com",
        value={"days_left": 43}, source="shauron", coverage="full",
        observed_at=base + datetime.timedelta(seconds=5)))
    session.commit()

    second = models.ScanJob(
        org_id=org.id, scanner="shauron-surface", capability="network",
        principal="tester", status="finished", origin="cloud", executor="shauron",
        targets=json.dumps([{"type": "domain", "value": "api.example.com"}]),
        profile=json.dumps({"name": "recon.simple"}),
        created_at=models.utcnow(), started_at=models.utcnow(),
        finished_at=models.utcnow() + datetime.timedelta(seconds=40))
    session.add(second)
    session.flush()
    now = models.utcnow()
    session.add_all([
        models.Observation(org_id=org.id, asset_id=asset.id, kind="certificate",
                           subject="api.example.com", value={"days_left": 12},
                           source="shauron", coverage="full",
                           observed_at=now + datetime.timedelta(seconds=5)),
        models.Observation(org_id=org.id, asset_id=asset.id, kind="web_path",
                           subject="api.example.com", value={"status": 200},
                           source="shauron", coverage="full",
                           observed_at=now + datetime.timedelta(seconds=6)),
    ])
    session.commit()

    result = surface_diff.build(session, second)
    assert result["available"] is True
    assert result["previous_run_id"] == first.id
    assert result["counts"] == {"new": 1, "gone": 0, "changed": 1}
    assert "1 new" in result["headline"] and "1 changed" in result["headline"]
    assert result["changed"][0]["field"] == "days_left"
    assert result["changed"][0]["before"] == 43 and result["changed"][0]["after"] == 12


def test_the_first_run_says_why_there_is_nothing_to_compare(env):
    from backend.app import surface_diff

    client, headers, _session, _org = env
    started = client.post("/api/v1/surface/runs",
                          json={"profile": "recon.simple", "targets": [TARGET]},
                          headers=headers).json()
    client.post(f"/api/v1/surface/runs/{started['run_id']}/finish",
                json={"ok": True, "manifest": {"coverage": "full"}}, headers=headers)
    flow = client.get(f"/api/v1/surface/runs/{started['run_id']}", headers=headers).json()
    assert flow["diff"]["available"] is False
    assert "first finished run" in flow["diff"]["reason"]


def test_redteam_never_runs_on_an_override(env):
    """An admin may scan their own host without a grant. Sending payloads is the
    one thing the authorization model exists for, so the plan is composed as the
    collector and every intrusive step is judged by the grant."""
    client, headers, session, org = env
    body = client.post("/api/v1/surface/plan",
                       json={"profile": "web.redteam", "targets": [WEB_TARGET],
                             "plane": "cloud"}, headers=headers).json()
    assert body["plan"]["requires_grant"] is True
    assert body["plan"]["basis"] == "grant"
    steps = [step for stage in body["plan"]["stages"] for step in stage["steps"]]
    assert {step["state"] for step in steps} == {"not_authorized"}
    # Not even the owner's own run can be created without it.
    response = client.post("/api/v1/surface/runs",
                           json={"profile": "web.redteam", "targets": [WEB_TARGET],
                                 "plane": "cloud"}, headers=headers)
    assert response.status_code == 409
    assert "grant" in response.json()["detail"].lower()


def test_redteam_still_runs_with_a_grant_that_covers_intrusive_testing(env):
    client, headers, session, org = env
    _grant(session, org, ["https://api.example.com"],
           capabilities="passive_discovery,active_verification,"
                        "vulnerability_analysis,intrusive_testing",
           target_type="url")
    body = client.post("/api/v1/surface/plan",
                       json={"profile": "web.redteam", "targets": [WEB_TARGET],
                             "plane": "cloud"}, headers=headers).json()
    steps = [step for stage in body["plan"]["stages"] for step in stage["steps"]]
    assert {step["state"] for step in steps} == {"allow"}
    assert body["plan"]["basis"] == "grant"


def test_a_rerun_replaces_its_step_instead_of_adding_one(env):
    """A requeued run writes a second set of step events. Showing both made the
    console report a failure that a later attempt had already fixed."""
    client, headers, session, org = env
    started = client.post("/api/v1/surface/runs",
                          json={"profile": "recon.simple", "targets": [TARGET],
                                "plane": "cloud"}, headers=headers)
    assert started.status_code == 201, started.text
    run_id = started.json()["run_id"]

    for status, detail in (("failed", "httpx produced no output: exit 1"),
                           ("ok", None)):
        body = client.post(f"/api/v1/surface/runs/{run_id}/steps",
                           json={"steps": [{"step": "probe.httpx", "stage": "probe",
                                            "status": status,
                                            "counters": {"live": 1} if status == "ok" else {},
                                            "error": detail}],
                                 "actor": "worker"}, headers=headers)
        assert body.status_code in (200, 201), body.text

    run = client.get(f"/api/v1/surface/runs/{run_id}", headers=headers).json()
    httpx_steps = [step for step in run["steps"] if step["step"] == "probe.httpx"]
    assert len(httpx_steps) == 1, httpx_steps
    assert httpx_steps[0]["status"] == "ok"
    assert "failed" not in run["verdict"]


def test_a_list_of_records_is_compared_as_a_bag_not_a_sequence():
    """14 discovered paths are 14 facts. ffuf reports them in finishing order, so
    comparing positionally reported "1 changed" on identical runs — and printing
    the raw list gave the reader `[object Object]` fourteen times."""
    from backend.app import surface_diff

    before = [{"path": "/admin", "status": 200}, {"path": "/.git/config", "status": 301}]
    after = [{"path": "/.git/config", "status": 301}, {"path": "/admin", "status": 200}]
    assert surface_diff._same(before, after) is True
    assert surface_diff._render(before) == ["/admin", "/.git/config"]


def test_a_real_path_change_is_still_a_change():
    from backend.app import surface_diff

    before = [{"path": "/admin", "status": 200}]
    after = [{"path": "/admin", "status": 200}, {"path": "/backup.zip", "status": 200}]
    assert surface_diff._same(before, after) is False


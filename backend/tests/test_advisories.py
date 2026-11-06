"""The advisory clock: due-ness, isolation, and the promise not to delete.

These tests never touch the network: the three fetchers are injectable on
purpose, because a job that only works when OSV is up cannot be verified.
"""
import datetime
import json
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import advisories, models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/advisories.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "clock")
    session.commit()
    yield {"app": app, "session": session, "org": org, "key": key}
    session.close()


def _project(session, org, slug="aurea", component="web"):
    project = models.Project(org_id=org.id, name=slug.title(), slug=slug)
    session.add(project)
    session.flush()
    application = models.ApplicationComponent(org_id=org.id, project_id=project.id,
                                              name=component, slug=component)
    session.add(application)
    session.flush()
    return project, application


def _version(session, org, purls=("pkg:npm/lodash@4.17.21",)):
    project, application = _project(session, org)
    version = models.ProjectVersion(project_id=project.id, component_id=application.id,
                                    version="1.0")
    session.add(version)
    session.flush()
    for purl in purls:
        component = models.Component(org_id=org.id, identity_key=purl, purl=purl,
                                     name=purl.split("/")[-1].split("@")[0],
                                     version=purl.rsplit("@", 1)[-1])
        session.add(component)
        session.flush()
        session.add(models.VersionComponent(project_version_id=version.id,
                                            component_id=component.id))
    session.commit()
    return project, version


class Fake:
    """Records what the job asked for; answers with the counters vulns.analyze does."""

    def __init__(self, created=1, refreshed=0, error=None):
        self.calls = []
        self.created = created
        self.refreshed = refreshed
        self.error = error

    def __call__(self, session, org_id, project, version):
        if self.error:
            raise self.error
        self.calls.append((project.slug, version.version))
        return {"components_queried": 1, "components_skipped_unmapped": 0,
                "advisories_found": 1, "findings_created": self.created,
                "findings_refreshed": self.refreshed, "truncated": False}


def test_first_run_is_due_and_awards_counts(env):
    session, org = env["session"], env["org"]
    _version(session, org)
    analyze = Fake(created=2)
    result = advisories.run(session, org.id, analyze=analyze,
                            kev_fetch=lambda: [], epss_fetch=lambda cve_ids: [])
    assert result["status"] == "ok"
    assert result["versions_analyzed"] == 1
    assert result["findings_created"] == 2
    assert analyze.calls == [("aurea", "1.0")]
    session.commit()


def test_second_run_inside_the_interval_is_not_due(env):
    session, org = env["session"], env["org"]
    _version(session, org)
    analyze = Fake()
    advisories.run(session, org.id, analyze=analyze,
                   kev_fetch=lambda: [], epss_fetch=lambda cve_ids: [])
    session.commit()
    again = advisories.run(session, org.id, analyze=analyze,
                           kev_fetch=lambda: [], epss_fetch=lambda cve_ids: [])
    assert again["status"] == "not_due"
    assert analyze.calls == [("aurea", "1.0")], "a not-due tick must not call OSV"
    session.commit()


def test_force_ignores_the_interval(env):
    session, org = env["session"], env["org"]
    _version(session, org)
    analyze = Fake()
    advisories.run(session, org.id, analyze=analyze,
                   kev_fetch=lambda: [], epss_fetch=lambda cve_ids: [])
    forced = advisories.run(session, org.id, force=True, analyze=analyze,
                            kev_fetch=lambda: [], epss_fetch=lambda cve_ids: [])
    assert forced["status"] == "ok"
    assert len(analyze.calls) == 2
    session.commit()


def test_disabled_job_does_nothing(env):
    session, org = env["session"], env["org"]
    _version(session, org)
    advisories.save(session, {"enabled": False})
    analyze = Fake()
    result = advisories.run(session, org.id, force=True, analyze=analyze,
                            kev_fetch=lambda: [], epss_fetch=lambda cve_ids: [])
    assert result["status"] == "disabled"
    assert analyze.calls == []
    session.commit()


def test_one_broken_build_does_not_abort_the_sweep(env):
    session, org = env["session"], env["org"]
    _version(session, org, purls=("pkg:npm/lodash@4.17.21",))
    _project_two = _project(session, org, slug="saria", component="api")[0]
    application_two = (session.query(models.ApplicationComponent)
                       .filter_by(project_id=_project_two.id).one())
    second = models.ProjectVersion(project_id=_project_two.id,
                                   component_id=application_two.id, version="2.0")
    session.add(second)
    session.flush()
    component = models.Component(org_id=org.id, identity_key="pkg:pypi/django@5.1",
                                 purl="pkg:pypi/django@5.1", name="django", version="5.1")
    session.add(component)
    session.flush()
    session.add(models.VersionComponent(project_version_id=second.id,
                                        component_id=component.id))
    session.commit()

    seen = []

    def analyze(session, org_id, project, version):
        seen.append((project.slug, version.version))
        if project.slug == "saria":
            raise RuntimeError("osv exploded")
        return {"components_queried": 1, "findings_created": 1, "findings_refreshed": 0,
                "advisories_found": 1, "components_skipped_unmapped": 0, "truncated": False}

    result = advisories.run(session, org.id, analyze=analyze,
                            kev_fetch=lambda: [], epss_fetch=lambda cve_ids: [])
    assert sorted(seen) == [("aurea", "1.0"), ("saria", "2.0")]
    assert result["versions_analyzed"] == 1
    assert result["findings_created"] == 1
    assert result["errors"][0]["version"] == "saria/2.0"
    assert result["status"] == "ok", "un build roto no vuelve fallido el barrido"
    session.commit()


def test_feeds_are_merged_and_epss_only_asks_for_held_cves(env):
    session, org = env["session"], env["org"]
    _version(session, org)
    session.add(models.Vulnerability(source_id="GHSA-1", source="osv", cve_id="CVE-2020-1"))
    session.commit()
    asked = {}

    def epss(cve_ids=None):
        asked["ids"] = cve_ids
        return [{"cve_id": "CVE-2020-1", "epss": "0.12", "percentile": "0.9"}]

    def kev():
        return [{"cve_id": "CVE-2020-1", "title": "x", "date_added": "2020-01-01",
                 "due_date": "2020-02-01", "source": "cisa"}]

    result = advisories.run(session, org.id, analyze=Fake(), kev_fetch=kev, epss_fetch=epss)
    assert result["kev_rows"] == 1
    assert result["epss_rows"] == 1
    assert asked["ids"] == ["CVE-2020-1"], "EPSS must answer for the catalogue, not the top 500"
    assert session.get(models.KevEntry, "CVE-2020-1") is not None
    assert session.get(models.EpssScore, "CVE-2020-1") is not None
    session.commit()


def test_a_feed_outage_does_not_skip_the_osv_pass(env):
    session, org = env["session"], env["org"]
    _version(session, org)

    def boom():
        raise OSError("no route to cisa")

    analyze = Fake(created=1)
    result = advisories.run(session, org.id, analyze=analyze, kev_fetch=boom,
                            epss_fetch=lambda cve_ids: [])
    assert result["errors"][0]["source"] == "kev"
    assert result["versions_analyzed"] == 1, "un feed caído no cancela el barrido"
    session.commit()


def test_settings_survive_a_run_and_clamp_out_of_range_values(env):
    session, org = env["session"], env["org"]
    saved = advisories.save(session, {"interval_hours": 999, "max_versions": 0,
                                      "ecosystems": ["npm", "not-a-thing"]})
    assert saved["interval_hours"] == 168
    assert saved["max_versions"] == 1
    assert saved["ecosystems"] == ["npm"]
    advisories.run(session, org.id, analyze=Fake(), kev_fetch=lambda: [],
                   epss_fetch=lambda cve_ids: [])
    session.commit()
    # Writing the settings again must not erase the record of the last run.
    after = advisories.save(session, {"interval_hours": 6})
    session.commit()
    loaded = advisories.load(session)
    assert loaded["source"] == "database"
    assert after["last_tick_at"] is not None
    assert loaded["last_tick_at"] is not None, "guardar settings no borra la última corrida"
    assert loaded["interval_hours"] == 6


def test_corrupt_row_falls_back_to_defaults(env):
    session = env["session"]
    session.add(models.PlatformSetting(name=advisories.ROW_NAME, value="{not json"))
    session.commit()
    loaded = advisories.load(session)
    assert loaded["unreadable_row"] is True
    assert loaded["enabled"] is True
    assert loaded["interval_hours"] == 24


def test_only_the_newest_build_of_each_component_is_re_resolved(env):
    session, org = env["session"], env["org"]
    project, old = _version(session, org)
    component = (session.query(models.Component).one())
    new = models.ProjectVersion(project_id=project.id, component_id=old.component_id,
                                version="2.0")
    session.add(new)
    session.flush()
    session.add(models.VersionComponent(project_version_id=new.id,
                                        component_id=component.id))
    new.created_at = models.utcnow() + datetime.timedelta(minutes=1)
    session.commit()
    analyze = Fake()
    advisories.run(session, org.id, analyze=analyze,
                   kev_fetch=lambda: [], epss_fetch=lambda cve_ids: [])
    assert analyze.calls == [("aurea", "2.0")]
    session.commit()


def test_the_same_cve_under_two_advisory_ids_is_one_finding(env):
    """Trivy names a CVE, OSV names its GHSA. One advisory, one row."""
    from backend.app import vulns

    session, org = env["session"], env["org"]
    project, version = _version(session, org, purls=("pkg:npm/lodash@4.17.21",))
    component = session.query(models.Component).one()
    # What the artifact reported: its own advisory id, same CVE.
    advisory = models.Vulnerability(source_id="CVE-2021-23337", source="sbom",
                                    cve_id="CVE-2021-23337", title="command injection",
                                    severity="HIGH")
    session.add(advisory)
    session.flush()
    session.add(models.Finding(org_id=org.id, project_id=project.id, kind="vulnerability",
                               fingerprint="artifact", source="sbom", title="command injection",
                               severity="HIGH", component_id=component.id,
                               vulnerability_id=advisory.id,
                               last_seen_version_id=version.id,
                               first_seen_at=models.utcnow(), last_seen_at=models.utcnow()))
    session.commit()

    def fetch(queries):
        return [{"vulns": [{"id": "GHSA-35jh-r3h4-6jhm",
                            "modified": "2026-01-01T00:00:00Z"}]} for _ in queries]

    def fetch_one(source_id):
        return {"id": source_id, "aliases": ["CVE-2021-23337"],
                "summary": "command injection in lodash",
                "modified": "2026-01-01T00:00:00Z",
                "database_specific": {"severity": "HIGH"}}

    counters = vulns.analyze(session, org.id, project, version,
                             fetch=fetch, fetch_one=fetch_one)
    session.commit()
    assert counters["advisories_found"] == 1
    assert counters["findings_created"] == 0, "el mismo CVE no crea una segunda fila"
    assert counters["findings_refreshed"] == 1
    rows = (session.query(models.Finding)
            .filter_by(component_id=component.id, kind="vulnerability").all())
    assert len(rows) == 1


def test_run_all_sweeps_every_organization_in_one_due_window(env):
    """The settings row is deployment-wide, so `last_tick_at` is too."""
    session, org = env["session"], env["org"]
    _version(session, org)
    second = models.Organization(slug="other", name="Other")
    session.add(second)
    session.flush()
    project = models.Project(org_id=second.id, name="Saria", slug="saria")
    session.add(project)
    session.flush()
    version = models.ProjectVersion(project_id=project.id, version="1.0")
    session.add(version)
    session.flush()
    component = models.Component(org_id=second.id, identity_key="pkg:pypi/django@5.1",
                                 purl="pkg:pypi/django@5.1", name="django", version="5.1")
    session.add(component)
    session.flush()
    session.add(models.VersionComponent(project_version_id=version.id,
                                        component_id=component.id))
    session.commit()

    analyze = Fake()
    result = advisories.run_all(session, analyze=analyze, kev_fetch=lambda: [],
                                epss_fetch=lambda cve_ids: [])
    assert result["organizations"] == 2
    assert result["versions_analyzed"] == 2
    assert sorted(analyze.calls) == [("aurea", "1.0"), ("saria", "1.0")]
    session.commit()


def test_the_clock_is_off_unless_the_deployment_starts_it(env, monkeypatch):
    monkeypatch.delenv("ADVISORIES_AUTORUN", raising=False)
    assert advisories.autorun_enabled() is False
    assert advisories.start_worker(lambda: env["session"]) is None
    assert advisories.load(env["session"])["autorun"] is False


def test_poll_seconds_are_bounded(monkeypatch):
    monkeypatch.setenv("ADVISORIES_POLL_SECONDS", "0")
    assert advisories.poll_seconds() == 5
    monkeypatch.setenv("ADVISORIES_POLL_SECONDS", "nonsense")
    assert advisories.poll_seconds() == 300
    monkeypatch.setenv("ADVISORIES_POLL_SECONDS", "999999")
    assert advisories.poll_seconds() == 86400


def test_one_clock_iteration_records_the_run(env):
    """The exact path the thread runs; a `sessionmaker` here would be silent."""
    from backend.app.db import session_factory

    _version(env["session"], env["org"])
    # Sources off: this asserts the wiring (open → decide → record → commit),
    # not the network, so the iteration is instant and repeatable.
    advisories.save(env["session"], {"kev": False, "epss": False, "osv": False})
    env["session"].commit()
    counters = advisories.tick_once(lambda: session_factory()())
    assert counters["status"] == "ok"
    assert advisories.load(session_factory()())["last_tick_at"] is not None


def test_a_sessionmaker_instead_of_a_session_is_refused_loudly(env):
    from backend.app.db import session_factory

    with pytest.raises(TypeError, match="sessionmaker"):
        advisories.tick_once(session_factory)


def _channel(session, org, events, name="ops"):
    session.add(models.NotificationChannel(
        org_id=org.id, name=name, kind="webhook", url="https://hooks.example.test/barad",
        secret="s3cret", events=json.dumps(events), enabled=True))
    session.commit()


def _new_finding(session, org, project, version, component, severity="CRITICAL",
                 cve="CVE-2026-1"):
    advisory = models.Vulnerability(source_id=f"GHSA-{cve}", source="osv", cve_id=cve,
                                    title="rce in a dependency", severity=severity)
    session.add(advisory)
    session.flush()
    finding = models.Finding(org_id=org.id, project_id=project.id, kind="vulnerability",
                             fingerprint=f"fp-{cve}", source="osv",
                             title="rce in a dependency", severity=severity,
                             component_id=component.id, vulnerability_id=advisory.id,
                             last_seen_version_id=version.id,
                             first_seen_at=models.utcnow(), last_seen_at=models.utcnow())
    session.add(finding)
    session.flush()
    return finding


def test_new_advisories_reach_the_subscribed_channel_once(env, monkeypatch):
    """The clock's output is only useful if somebody is told."""
    from backend.app.routers import notifications

    session, org = env["session"], env["org"]
    project, version = _version(session, org)
    component = session.query(models.Component).one()
    _channel(session, org, ["advisory.new"])
    finding = _new_finding(session, org, project, version, component)
    session.add(models.KevEntry(cve_id="CVE-2026-1", title="x", fetched_at=models.utcnow()))
    session.commit()

    sent = []
    monkeypatch.setattr(notifications, "deliver",
                        lambda channel, event, payload, session=None: (sent.append(payload) or (200, None)))

    counters = advisories.run(session, org.id, force=True,
                              kev_fetch=lambda: [], epss_fetch=lambda cve_ids: [],
                              analyze=lambda *args, **kwargs: {
                                  "components_queried": 1, "findings_created": 1,
                                  "findings_refreshed": 0, "advisories_found": 1,
                                  "components_skipped_unmapped": 0, "truncated": False,
                                  "created_ids": [finding.id]})
    session.commit()
    assert counters["notified"] == ["ops:sent"]
    assert len(sent) == 1
    assert sent[0]["count"] == 1
    assert sent[0]["kev"] == 1, "KEV es un hecho: se cuenta en el aviso"
    assert sent[0]["worst"] == "CRITICAL"
    assert "aurea" in sent[0]["builds"]
    delivery = session.query(models.NotificationDelivery).one()
    assert delivery.event == "advisory.new" and delivery.status == "sent"

    # A second sweep the same day must not repeat itself.
    again = advisories.run(session, org.id, force=True,
                           kev_fetch=lambda: [], epss_fetch=lambda cve_ids: [],
                           analyze=lambda *args, **kwargs: {
                               "findings_created": 1, "created_ids": [finding.id],
                               "components_queried": 1, "findings_refreshed": 0,
                               "advisories_found": 1, "components_skipped_unmapped": 0,
                               "truncated": False})
    session.commit()
    assert again["notified"] == ["ops:already_sent"]
    assert session.query(models.NotificationDelivery).count() == 1
    assert len(sent) == 1


def test_a_quiet_sweep_says_nothing(env, monkeypatch):
    from backend.app.routers import notifications

    session, org = env["session"], env["org"]
    _version(session, org)
    _channel(session, org, ["advisory.new"])
    sent = []
    monkeypatch.setattr(notifications, "deliver",
                        lambda *args, **kwargs: (sent.append(args) or (200, None)))
    counters = advisories.run(session, org.id, force=True,
                              kev_fetch=lambda: [], epss_fetch=lambda cve_ids: [],
                              analyze=lambda *args, **kwargs: {
                                  "findings_created": 0, "created_ids": [],
                                  "components_queried": 1, "findings_refreshed": 5,
                                  "advisories_found": 5, "components_skipped_unmapped": 0,
                                  "truncated": False})
    session.commit()
    assert counters["notified"] == []
    assert sent == [], "sin novedades no se manda nada"


def test_a_channel_that_did_not_subscribe_is_not_used(env, monkeypatch):
    from backend.app.routers import notifications

    session, org = env["session"], env["org"]
    project, version = _version(session, org)
    component = session.query(models.Component).one()
    _channel(session, org, ["sla.breached"], name="sla-only")
    finding = _new_finding(session, org, project, version, component, cve="CVE-2026-2")
    session.commit()
    sent = []
    monkeypatch.setattr(notifications, "deliver",
                        lambda *args, **kwargs: (sent.append(args) or (200, None)))
    counters = advisories.run(session, org.id, force=True,
                              kev_fetch=lambda: [], epss_fetch=lambda cve_ids: [],
                              analyze=lambda *args, **kwargs: {
                                  "findings_created": 1, "created_ids": [finding.id],
                                  "components_queried": 1, "findings_refreshed": 0,
                                  "advisories_found": 1, "components_skipped_unmapped": 0,
                                  "truncated": False})
    session.commit()
    assert counters["notified"] == []
    assert sent == []


def test_api_reports_settings_and_runs_a_tick(env):
    from fastapi.testclient import TestClient

    client = TestClient(env["app"])
    headers = {"X-API-Key": env["key"]}
    read = client.get("/api/v1/advisories/settings", headers=headers)
    assert read.status_code == 200
    assert read.json()["data"]["interval_hours"] == 24
    # No network in tests: the sources are switched off before the tick, and the
    # job still answers with its counters instead of reaching for OSV/CISA.
    written = client.put("/api/v1/advisories/settings", headers=headers,
                         json={"osv": False, "kev": False, "epss": False,
                               "interval_hours": 6})
    assert written.status_code == 200
    assert written.json()["data"]["osv"] is False
    assert written.json()["data"]["interval_hours"] == 6
    tick = client.post("/api/v1/advisories/tick", headers=headers,
                       json={"actor": "test", "force": True})
    assert tick.status_code == 200
    assert tick.json()["data"]["status"] == "ok"

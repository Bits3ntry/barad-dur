"""BL-055 acceptance: deterministic quality gates."""
import json
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
def gate_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/gate.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    key = create_key(session, org.id, "gate")
    other_key = create_key(session, other.id, "gate2")
    project = models.Project(org_id=org.id, slug="gated", name="gated")
    session.add(project)
    session.flush()
    session.add(models.ProjectVersion(project_id=project.id, version="1.0"))
    session.commit()
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key},
            {"X-API-Key": other_key}, session, project)


def _ingest(test_client, headers, severity="HIGH", rule="r-1"):
    return test_client.post(
        "/api/v1/findings/ingest?project=gated&version=1.0",
        json={"schema": "barad-findings-v1", "tool": "opengrep",
              "findings": [{"kind": "code-weakness", "title": f"issue {rule}",
                            "severity": severity, "rule_id": rule,
                            "path": "app.py"}]},
        headers=headers)


def test_gate_fails_on_threshold_and_passes_after_resolution(gate_client):
    test_client, headers, _other, _session, _project = gate_client
    test_client.post("/api/v1/gate-policies", json={
        "name": "standard", "max_severity": "HIGH", "actor": "sec"}, headers=headers)
    _ingest(test_client, headers, severity="HIGH")
    verdict = test_client.post("/api/v1/gates/evaluate",
                               json={"project": "gated", "version": "1.0"},
                               headers=headers).json()["data"]
    assert verdict["verdict"] == "fail"
    assert verdict["rules"][0]["rule"] == "severity_threshold"
    assert verdict["rules"][0]["status"] == "fail"
    assert verdict["reasons"]
    assert verdict["policy_version"] == 1

    finding_id = test_client.get("/api/v1/findings", headers=headers).json()["data"][0]["id"]
    test_client.patch(f"/api/v1/findings/{finding_id}/status",
                      json={"status": "resolved", "reason": "fixed in PR",
                            "actor": "dev"}, headers=headers)
    after = test_client.post("/api/v1/gates/evaluate",
                             json={"project": "gated", "version": "1.0"},
                             headers=headers).json()["data"]
    assert after["verdict"] == "pass"


def test_gate_threshold_respected(gate_client):
    test_client, headers, _other, _session, _project = gate_client
    test_client.post("/api/v1/gate-policies", json={
        "name": "critical-only", "max_severity": "CRITICAL", "actor": "sec"},
        headers=headers)
    _ingest(test_client, headers, severity="HIGH")
    verdict = test_client.post("/api/v1/gates/evaluate",
                               json={"project": "gated", "version": "1.0"},
                               headers=headers).json()["data"]
    assert verdict["verdict"] == "pass"
    _ingest(test_client, headers, severity="CRITICAL", rule="r-crit")
    again = test_client.post("/api/v1/gates/evaluate",
                             json={"project": "gated", "version": "1.0"},
                             headers=headers).json()["data"]
    assert again["verdict"] == "fail"


def test_suppressed_findings_do_not_fail_gate(gate_client):
    test_client, headers, _other, _session, _project = gate_client
    test_client.post("/api/v1/gate-policies", json={
        "name": "std", "max_severity": "LOW", "actor": "sec"}, headers=headers)
    _ingest(test_client, headers, severity="MEDIUM", rule="fp")
    rule = test_client.post("/api/v1/suppressions", json={
        "kind": "code-weakness", "rule_id": "fp", "path_pattern": "app.py",
        "suppression_type": "accepted_risk", "reason": "known false positive",
        "requested_by": "sec"}, headers=headers).json()
    test_client.post(f"/api/v1/suppressions/{rule['data']['id']}/approve",
                     json={"approver": "reviewer"}, headers=headers)
    verdict = test_client.post("/api/v1/gates/evaluate",
                               json={"project": "gated", "version": "1.0"},
                               headers=headers).json()["data"]
    assert verdict["verdict"] == "pass"


def test_project_policy_overrides_org(gate_client):
    test_client, headers, _other, _session, project = gate_client
    test_client.post("/api/v1/gate-policies", json={
        "name": "org", "max_severity": "LOW", "actor": "sec"}, headers=headers)
    test_client.post("/api/v1/gate-policies", json={
        "name": "relaxed", "scope_type": "project", "scope_id": project.id,
        "max_severity": "CRITICAL", "actor": "sec"}, headers=headers)
    _ingest(test_client, headers, severity="MEDIUM")
    verdict = test_client.post("/api/v1/gates/evaluate",
                               json={"project": "gated", "version": "1.0"},
                               headers=headers).json()["data"]
    assert verdict["policy"]["name"] == "relaxed"
    assert verdict["verdict"] == "pass"


def test_kev_rule_blocks_when_configured(gate_client):
    test_client, headers, _other, session, _project = gate_client
    # craft a vulnerability finding tied to a KEV advisory
    from backend.app import vulns
    import datetime
    org = session.query(models.Organization).filter_by(slug="poc").one()
    project = session.query(models.Project).filter_by(slug="gated").one()
    version = session.query(models.ProjectVersion).one()
    component = models.Component(
        org_id=org.id, identity_key="pkg:pypi/kevlib@1.0", name="kevlib",
        version="1.0", purl="pkg:pypi/kevlib@1.0",
        created_at=models.utcnow(), updated_at=models.utcnow())
    session.add(component)
    session.flush()
    session.add(models.VersionComponent(project_version_id=version.id,
                                        component_id=component.id))
    advisory = models.Vulnerability(source_id="GHSA-kev", cve_id="CVE-2024-1111",
                                    title="kev bug", severity="LOW", url=None,
                                    created_at=models.utcnow())
    session.add(advisory)
    session.flush()
    now = datetime.datetime.now(datetime.timezone.utc)
    session.add(models.Finding(
        org_id=org.id, project_id=project.id, kind="vulnerability",
        fingerprint=vulns.vulnerability_fingerprint(org.id, project.id,
                                                    component.identity_key,
                                                    "GHSA-kev"),
        source="osv", title="kev bug", severity="LOW",
        component_id=component.id, vulnerability_id=advisory.id,
        last_seen_version_id=version.id,
        first_seen_at=now, last_seen_at=now, updated_at=now))
    session.merge(models.KevEntry(cve_id="CVE-2024-1111", title="kev bug",
                                  date_added="2024-01-01",
                                  fetched_at=models.utcnow()))
    session.commit()

    test_client.post("/api/v1/gate-policies", json={
        "name": "kev-aware", "max_severity": "CRITICAL", "block_kev": True,
        "actor": "sec"}, headers=headers)
    verdict = test_client.post("/api/v1/gates/evaluate",
                               json={"project": "gated", "version": "1.0"},
                               headers=headers).json()["data"]
    kev_rule = next(r for r in verdict["rules"] if r["rule"] == "kev_exposure")
    assert kev_rule["status"] == "fail"
    assert verdict["verdict"] == "fail"


def test_tenant_isolation_and_audit(gate_client):
    test_client, headers, other_headers, _session, _project = gate_client
    test_client.post("/api/v1/gate-policies", json={
        "name": "tenant-policy", "actor": "sec"}, headers=headers)
    assert test_client.get("/api/v1/gate-policies",
                           headers=other_headers).json()["total"] == 0
    foreign = test_client.post("/api/v1/gates/evaluate",
                               json={"project": "gated"}, headers=other_headers)
    assert foreign.status_code == 404
    audit = test_client.get("/api/v1/audit?action=gate.", headers=headers).json()
    assert audit["total"] >= 1
    assert audit["chain_ok"] is True

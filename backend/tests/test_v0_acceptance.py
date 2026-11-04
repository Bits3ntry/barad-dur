"""v0 acceptance closure: dashboard consistency, queue visibility, cycle scope,
artifact → SBOM → deployment chain.

These tests are the evidence for the closure pass: a counter that does not equal
its destination list is a defect, an org-wide queue must say so, auto-linking must
not pull findings from outside the frozen selection, and an artifact must state
whether it has an SBOM at all.
"""
import json
import sys
from datetime import timedelta
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


@pytest.fixture()
def seeded(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/acceptance.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="bitsentry", name="Bitsentry")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    project = models.Project(org_id=org.id, name="AUREA", slug="aurea")
    session.add(project)
    session.flush()
    version = models.ProjectVersion(project_id=project.id, version="v3")
    session.add(version)
    graph_version = models.ProjectVersion(project_id=project.id, version="v2")
    session.add(graph_version)
    session.flush()
    component = models.ApplicationComponent(
        org_id=org.id, project_id=project.id, name="AUREA backend",
        slug="backend", kind="backend")
    repository = models.Repository(org_id=org.id, provider="git", name="aurea-api",
                                   remote_url="https://git.example.test/aurea-api.git")
    session.add_all([component, repository])
    session.flush()
    session.add(models.ProjectRepository(org_id=org.id, project_id=project.id,
                                         repository_id=repository.id, relation="builds"))
    artifact = models.Artifact(org_id=org.id, project_version_id=graph_version.id,
                               application_component_id=component.id,
                               name="aurea-api-v3", digest="sha256:graph-v3",
                               source="ci")
    session.add(artifact)
    session.flush()
    asset_a = models.Asset(org_id=org.id, type="domain",
                           value="api-aurea.bitsentry.xyz", source="scope",
                           project_id=project.id)
    asset_b = models.Asset(org_id=org.id, type="domain",
                           value="admin-aurea.bitsentry.xyz", source="manual",
                           project_id=project.id)
    session.add_all([asset_a, asset_b])
    session.flush()
    deployment = models.Deployment(org_id=org.id, name="aurea-backend",
                                   environment="production", artifact_id=artifact.id,
                                   application_component_id=component.id)
    session.add(deployment)
    session.flush()
    staging = models.Deployment(org_id=org.id, name="aurea-backend-staging",
                                environment="staging", status="planned")
    session.add(staging)
    session.flush()
    session.add_all([
        models.AssetLink(org_id=org.id, asset_id=asset_a.id,
                         entity_type="deployment", entity_id=deployment.id),
        models.AssetLink(org_id=org.id, asset_id=asset_b.id,
                         entity_type="deployment", entity_id=staging.id),
    ])
    session.add(models.WebEndpoint(org_id=org.id, asset_id=asset_a.id,
                                   origin="https://api-aurea.bitsentry.xyz", path="/health",
                                   method="GET", state="observed", status_code=200,
                                   discovery_source="test"))

    def finding(title, status, severity="HIGH", priority="P1", **extra):
        row = models.Finding(
            org_id=org.id, project_id=project.id, kind="code-weakness",
            fingerprint=f"fp-{title}", source="manual", title=title,
            severity=severity, priority=priority, status=status,
            first_seen_at=models.utcnow(), last_seen_at=models.utcnow(), **extra)
        session.add(row)
        session.flush()
        return row

    open_finding = finding("IDOR invoices", "open", cwe="CWE-639")
    ack = finding("Weak TLS", "acknowledged", severity="MEDIUM")
    finding("Closed one", "resolved", severity="LOW")
    finding("Suppressed one", "suppressed", severity="LOW")
    session.add_all([
        models.FindingContext(org_id=org.id, finding_id=open_finding.id,
                              entity_type="asset", entity_id=asset_a.id),
    ])
    advisory = models.Vulnerability(source_id="GHSA-1", source="osv",
                                    cve_id="CVE-2026-1111", title="django",
                                    severity="HIGH")
    session.add(advisory)
    session.flush()
    session.add(models.Finding(
        org_id=org.id, project_id=project.id, kind="vulnerability",
        fingerprint="fp-cve", source="osv", title="django issue",
        severity="HIGH", status="open", vulnerability_id=advisory.id,
        first_seen_at=models.utcnow(), last_seen_at=models.utcnow()))
    session.add(models.ExposureEvent(
        org_id=org.id, asset_id=asset_a.id, stable_key="k1", kind="open_port",
        title="port 8080", severity="MEDIUM", state="open",
        first_seen_at=models.utcnow(), last_seen_at=models.utcnow()))
    session.add(models.Cycle(org_id=org.id, name="Q4", state="active",
                             created_at=models.utcnow(), updated_at=models.utcnow()))
    session.add(models.WorkItem(
        org_id=org.id, kind="acceptance", title="fw exception", status="accepted",
        requested_by="bob", reviewer="ana",
        valid_until=models.utcnow() + timedelta(days=10),
        updated_at=models.utcnow()))
    session.add(models.WorkItem(
        org_id=org.id, kind="task", title="someone else task", status="open",
        assignee="bob", requested_by="bob", updated_at=models.utcnow()))
    key = create_key(session, org.id, "acceptance")
    other_key = create_key(session, other.id, "acceptance-other")
    session.commit()
    from fastapi.testclient import TestClient
    return (TestClient(app), {"X-API-Key": key}, {"X-API-Key": other_key},
            {"project": "aurea", "version": "v3", "asset_a": asset_a.id,
             "asset_b": asset_b.id, "deployment": deployment.id,
             "finding": open_finding.id})


def test_dashboard_rejects_an_unknown_project_instead_of_widening(seeded):
    client, headers = seeded[0], seeded[1]
    assert client.get("/api/v1/dashboard/summary?project=nope",
                      headers=headers).status_code == 404
    assert client.get("/api/v1/dashboard/exposure-flow?project=nope",
                      headers=headers).status_code == 404


def test_project_runtime_graph_uses_only_the_project_evidence(seeded):
    client, headers, other_headers, _ids = seeded
    response = client.get("/api/v1/projects/aurea/runtime-graph", headers=headers)
    assert response.status_code == 200, response.text
    data = response.json()["data"]
    assert data["project"]["slug"] == "aurea"
    assert data["summary"]["components"] == 1
    assert data["summary"]["active_deployments"] == 1
    assert data["summary"]["assets"] == 2
    assert data["summary"]["registered_endpoints"] == 1
    kinds = {node["type"] for node in data["nodes"]}
    assert {"project", "application_component", "repository", "version", "artifact",
            "deployment", "asset", "endpoint", "finding"} <= kinds
    relations = {(edge["relation"], edge.get("evidence")) for edge in data["edges"]}
    assert ("runs_as", "declared") in relations
    assert ("has_registered", "observed") in relations
    assert client.get("/api/v1/projects/nope/runtime-graph", headers=headers).status_code == 404
    assert client.get("/api/v1/projects/aurea/runtime-graph", headers=other_headers).status_code == 404


def test_dashboard_counters_equal_their_destinations(seeded):
    test_client, headers, _other, _ids = seeded
    block = test_client.get("/api/v1/dashboard/v0", headers=headers).json()["data"]

    assets = test_client.get("/api/v1/assets", headers=headers).json()["total"]
    assert block["assets"]["value"] == assets
    assert block["assets"]["filters"] == {"include_archived": False}

    open_rows = test_client.get("/api/v1/findings?status=open",
                                headers=headers).json()["total"]
    ack_rows = test_client.get("/api/v1/findings?status=acknowledged",
                               headers=headers).json()["total"]
    assert block["findings"]["open"] == open_rows + ack_rows
    assert block["findings"]["filters"]["status"] == ["open", "acknowledged"]
    assert block["findings"]["by_severity"] == {**block["findings"]["by_severity"]}
    assert sum(block["findings"]["by_severity"].values()) == block["findings"]["open"]

    problems = test_client.get("/api/v1/vulnerabilities", headers=headers).json()
    # The list is every problem (code, credentials, configuration, dependencies);
    # `cves` is the dependency subset, and it must match the filtered list.
    assert block["vulnerabilities"]["problems"] == problems["total"]
    cves_only = test_client.get("/api/v1/vulnerabilities?vector=dependency-cve",
                                headers=headers).json()["total"]
    assert block["vulnerabilities"]["cves"] == cves_only

    exposures = test_client.get("/api/v1/exposures?state=open",
                                headers=headers).json()["total"]
    assert block["exposures"]["open"] == exposures

    cycles = test_client.get("/api/v1/cycles?state=active",
                             headers=headers).json()["total"]
    assert block["cycles"]["active"] == cycles
    assert block["expiries"]["acceptances_next_30d"] == 1
    for key in ("assets", "projects", "findings", "vulnerabilities",
                "recent_changes", "exposures", "cycles", "expiries"):
        assert block[key]["link"]
    assert "not that it is clean" in block["coverage"]["note"]

    other = test_client.get("/api/v1/dashboard/v0", headers=_other).json()["data"]
    assert other["findings"]["open"] == 0
    assert other["assets"]["value"] == 0


def test_org_queue_is_labelled_and_isolated(seeded):
    test_client, headers, other_headers, _ids = seeded
    trays = test_client.get("/api/v1/my-work?actor=ana",
                            headers=headers).json()["data"]["trays"]
    team = trays["my_team"]
    assert team["count"] == 1
    assert team["scope"] == "organization"
    assert team["supported"] is False
    assert "Organization queue" in team["label"]
    assert "no teams" in team["note"]

    isolated = test_client.get("/api/v1/my-work?actor=ana",
                               headers=other_headers).json()["data"]["trays"]
    assert isolated["my_team"]["count"] == 0
    assert isolated["assigned_to_me"]["count"] == 0


def test_auto_link_respects_the_frozen_selection(seeded):
    test_client, headers, _other, ids = seeded
    # A second finding of the same project whose location is the other asset.
    session = session_factory()()
    org = session.query(models.Organization).filter_by(slug="bitsentry").one()
    project = session.query(models.Project).filter_by(slug="aurea").one()
    other_asset_finding = models.Finding(
        org_id=org.id, project_id=project.id, kind="code-weakness",
        fingerprint="fp-other-asset", source="manual", title="Admin panel weakness",
        severity="LOW", status="open",
        first_seen_at=models.utcnow(), last_seen_at=models.utcnow())
    session.add(other_asset_finding)
    session.flush()
    session.add(models.FindingContext(
        org_id=org.id, finding_id=other_asset_finding.id,
        entity_type="asset", entity_id=ids["asset_b"]))
    no_context = models.Finding(
        org_id=org.id, project_id=project.id, kind="code-weakness",
        fingerprint="fp-no-context", source="manual", title="Floating weakness",
        severity="LOW", status="open",
        first_seen_at=models.utcnow(), last_seen_at=models.utcnow())
    session.add(no_context)
    session.commit()
    session.close()

    cycle = test_client.post("/api/v1/cycles", json={
        "name": "Production only", "selection": {"environments": ["production"]},
        "actor": "tester"}, headers=headers).json()["data"]
    preview = test_client.post(f"/api/v1/cycles/{cycle['id']}/preview",
                               headers=headers).json()["data"]
    assert preview["by_type"].get("deployment") == 1
    test_client.post(f"/api/v1/cycles/{cycle['id']}/activate", headers=headers)

    result = test_client.post(f"/api/v1/cycles/{cycle['id']}/link-findings", json={
        "auto": True, "actor": "tester"}, headers=headers).json()["data"]
    assert result["linked"] == 1, "only the finding located on the frozen asset"
    reasons = " ".join(item["reason"] for item in result["skipped"])
    assert "no location among them" in reasons

    detail = test_client.get(f"/api/v1/cycles/{cycle['id']}", headers=headers).json()["data"]
    linked_ids = {row["id"] for row in detail["findings"]}
    assert ids["finding"] in {row["id"] for row in detail["findings"]}
    assert other_asset_finding.id not in linked_ids
    assert no_context.id not in linked_ids

    wide = test_client.post("/api/v1/cycles", json={
        "name": "Whole project", "selection": {"projects": ["aurea"]},
        "actor": "tester"}, headers=headers).json()["data"]
    test_client.post(f"/api/v1/cycles/{wide['id']}/activate", headers=headers)
    every = test_client.post(f"/api/v1/cycles/{wide['id']}/link-findings", json={
        "auto": True, "actor": "tester"}, headers=headers).json()["data"]
    assert every["linked"] >= 4, "a project-wide reference includes every finding"


def test_artifact_sbom_deployment_chain(seeded):
    test_client, headers, other_headers, ids = seeded
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "metadata": {"component": {"name": "aurea", "version": "v3"}},
            "components": [{"name": "django", "version": "3.2.0",
                            "purl": "pkg:pypi/django@3.2.0"}]}
    uploaded = test_client.post(
        "/api/v1/sbom?project=aurea&version=v3&source=ci"
        "&artifact_digest=sha256:abc123&artifact_name=aurea-backend-v3",
        content=json.dumps(sbom).encode(),
        headers={**headers, "Content-Type": "application/octet-stream"})
    assert uploaded.status_code in (200, 201), uploaded.text
    artifact = uploaded.json()["artifact"]
    assert artifact["digest"] == "sha256:abc123"

    listed = test_client.get("/api/v1/artifacts?project=aurea&version=v3",
                             headers=headers).json()
    assert listed["total"] == 1
    row = listed["data"][0]
    assert row["sbom_present"] is True
    assert row["components_in_version"] >= 1
    assert row["in_production"] is False

    deployed = test_client.post("/api/v1/deployments", json={
        "name": "aurea-backend-prod", "environment": "production",
        "artifact_id": row["id"], "status": "active",
        "deployed_at": "2026-11-01T10:00:00+00:00", "actor": "tester"},
        headers=headers)
    assert deployed.status_code == 200, deployed.text

    artifact_detail = test_client.get(f"/api/v1/artifacts/{row['id']}",
                                      headers=headers).json()["data"]
    assert artifact_detail["in_production"] is True
    assert artifact_detail["deployments"][0]["environment"] == "production"
    assert "not authorize testing" in artifact_detail["authorization"]

    deployments = test_client.get("/api/v1/deployments", headers=headers).json()["data"]
    assert any(item["version"] == "v3" for item in deployments)

    # An artifact with no SBOM says so instead of looking clean.
    manual = test_client.post("/api/v1/artifacts", json={
        "project": "aurea", "version": "v3", "name": "hotfix-build",
        "digest": "sha256:def456", "actor": "tester"}, headers=headers).json()["data"]
    assert manual["sbom_present"] is False
    assert "no SBOM is linked" in manual["coverage"]["sbom"]
    assert manual["coverage"]["usage_per_artifact"].startswith("not implemented")

    assert test_client.get(f"/api/v1/artifacts/{row['id']}",
                           headers=other_headers).status_code == 404
    assert test_client.get("/api/v1/artifacts", headers=other_headers).json()["total"] == 0

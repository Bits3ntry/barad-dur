"""SBOM baselines: freeze, read, delete and diff against the current set."""
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


def _sbom(components):
    return {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "metadata": {"component": {"type": "application", "name": "app"}},
            "components": [{"type": "library", "name": name, "version": version,
                            "purl": f"pkg:pypi/{name}@{version}"}
                           for name, version in components]}


@pytest.fixture()
def baseline_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/base.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    key = create_key(session, org.id, "base")
    other_key = create_key(session, other.id, "base2")
    session.commit()
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key}, {"X-API-Key": other_key})


def _ingest(test_client, headers, components, version="1.0"):
    return test_client.post(f"/api/v1/sbom?project=payments&version={version}",
                            content=json.dumps(_sbom(components)).encode(),
                            headers={**headers,
                                     "Content-Type": "application/octet-stream"})


def test_baseline_requires_components(baseline_client):
    test_client, headers, _other = baseline_client
    missing = test_client.post("/api/v1/sbom/baseline", json={
        "project": "payments", "version": "9.9", "actor": "santiago"},
        headers=headers)
    assert missing.status_code == 404
    _ingest(test_client, headers, [("requests", "2.31.0")])
    no_baseline = test_client.get("/api/v1/sbom/baseline",
                                  params={"project": "payments", "version": "1.0"},
                                  headers=headers)
    assert no_baseline.status_code == 404


def test_baseline_freeze_and_diff(baseline_client):
    test_client, headers, _other = baseline_client
    _ingest(test_client, headers, [("requests", "2.31.0"), ("urllib3", "1.26.5"),
                                   ("old-lib", "0.1")])
    created = test_client.post("/api/v1/sbom/baseline", json={
        "project": "payments", "version": "1.0", "note": "release 1.0",
        "actor": "santiago"}, headers=headers)
    assert created.status_code == 200, created.text
    # the ingest also records the application root component
    assert created.json()["data"]["component_count"] >= 3

    # same version, new SBOM content: requests bumped, certifi new.
    # Ingest is additive by contract, so a component only *disappears* when its
    # version link is removed; we simulate that cleanup explicitly below.
    _ingest(test_client, headers, [("requests", "2.32.3"), ("urllib3", "1.26.5"),
                                   ("certifi", "2024.2.2")])
    session = session_factory()()
    stale = (session.query(models.VersionComponent)
             .join(models.Component,
                   models.VersionComponent.component_id == models.Component.id)
             .filter(models.Component.name == "old-lib").one())
    session.delete(stale)
    session.commit()
    diff = test_client.get("/api/v1/sbom/baseline/diff",
                           params={"project": "payments", "version": "1.0"},
                           headers=headers).json()["data"]
    assert diff["counts"]["baseline"] >= 3
    assert diff["counts"]["current"] >= 3
    assert [row["name"] for row in diff["added"]] == ["certifi"]
    assert [row["name"] for row in diff["removed"]] == ["old-lib"]
    # additive ingest keeps the old link until cleanup, so the diff reports
    # every version present instead of pretending one of them vanished
    assert diff["changed"] == [{"name": "requests", "from": "2.31.0",
                                "to": "2.31.0, 2.32.3"}]
    assert diff["baseline_at"]

    # re-baselining freezes the new state: the diff becomes empty
    test_client.post("/api/v1/sbom/baseline", json={
        "project": "payments", "version": "1.0", "actor": "santiago"},
        headers=headers)
    empty = test_client.get("/api/v1/sbom/baseline/diff",
                            params={"project": "payments", "version": "1.0"},
                            headers=headers).json()["data"]
    assert empty["counts"]["added"] == 0
    assert empty["counts"]["removed"] == 0
    assert empty["counts"]["changed"] == 0

    deleted = test_client.delete("/api/v1/sbom/baseline",
                                 params={"project": "payments", "version": "1.0"},
                                 headers=headers)
    assert deleted.status_code == 200
    assert test_client.get("/api/v1/sbom/baseline/diff",
                           params={"project": "payments", "version": "1.0"},
                           headers=headers).status_code == 404


def test_baseline_is_tenant_scoped(baseline_client):
    test_client, headers, other_headers = baseline_client
    _ingest(test_client, headers, [("requests", "2.31.0")])
    test_client.post("/api/v1/sbom/baseline", json={
        "project": "payments", "version": "1.0", "actor": "santiago"},
        headers=headers)
    foreign = test_client.get("/api/v1/sbom/baseline/diff",
                              params={"project": "payments", "version": "1.0"},
                              headers=other_headers)
    assert foreign.status_code == 404

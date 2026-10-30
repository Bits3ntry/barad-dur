"""F0 acceptance tests: auth, SBOM ingestion, idempotency, inventory listing."""
import json
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT.parent))

from backend.app.auth import create_key  # noqa: E402
from backend.app import models  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "metadata": {
        "component": {
            "name": "poc-fixture",
            "version": "0.1.0",
            "bom-ref": "root",
            "type": "application",
        },
    },
    "components": [
        {"name": "requests", "version": "2.32.3", "bom-ref": "c1",
         "purl": "pkg:pypi/requests@2.32.3",
         "licenses": [{"license": {"id": "Apache-2.0"}}],
         "properties": [{"name": "SrcFile", "value": "requirements.txt"}]},
        {"name": "urllib3", "version": "2.2.1", "bom-ref": "c2",
         "purl": "pkg:pypi/urllib3@2.2.1"},
        {"name": "weirdlib-no-purl", "version": "9.9", "bom-ref": "c3"},
    ],
    "dependencies": [
        {"ref": "root", "dependsOn": ["c1", "c2"]},
        {"ref": "c1", "dependsOn": ["c2"]},
    ],
}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/poc-test.db")
    app = create_app()
    engine_session = session_factory()()
    models.Base.metadata.create_all(engine_session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    engine_session.add(org)
    engine_session.flush()
    raw_key = create_key(engine_session, org.id, "test-key")
    engine_session.close()
    from fastapi.testclient import TestClient

    test_client = TestClient(app)
    test_client.key = raw_key
    return test_client


def _post(client: object, doc: dict, **params):
    return client.post("/api/v1/sbom", content=json.dumps(doc).encode(),
                       headers={"X-API-Key": client.key}, params=params)


def test_healthz_ok(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_requires_api_key(client):
    response = client.post("/api/v1/sbom", content=b"{}")
    assert response.status_code == 401
    response = client.post("/api/v1/sbom", content=b"{}", headers={"X-API-Key": "nope"})
    assert response.status_code == 401


def test_ingest_creates_receipt_and_inventory(client):
    response = _post(client, SBOM, source="cli")
    assert response.status_code == 201, response.text
    body = response.json()
    receipt = body["receipt"]
    assert body["status"] == "created"
    assert receipt["project"] == "poc-fixture"
    assert receipt["version"] == "0.1.0"
    assert receipt["counts"]["components_received"] == 3
    assert receipt["counts"]["components_created"] == 3
    assert receipt["counts"]["links_created"] == 3

    listed = client.get("/api/v1/components", params={"project": "poc-fixture", "version": "0.1.0"},
                        headers={"X-API-Key": client.key})
    assert listed.status_code == 200
    rows = listed.json()["data"]
    by_purl = {row["identity_key"]: row for row in rows}
    assert len(rows) == 3
    requests_row = by_purl["pkg:pypi/requests@2.32.3"]
    assert requests_row["is_direct"] is True
    assert requests_row["license"] == "Apache-2.0"
    assert requests_row["manifest_path"] == "requirements.txt"
    urllib_row = by_purl["pkg:pypi/urllib3@2.2.1"]
    assert urllib_row["is_direct"] is True
    # c2 is a root child AND nested under c1 (diamond): direct stays True,
    # the tree parent records the nested parent.
    assert urllib_row["parent_purl"] == "pkg:pypi/requests@2.32.3"
    no_purl = by_purl["ref:c3"]
    assert no_purl["purl"] is None and no_purl["is_direct"] is False
    assert no_purl["parent_purl"] is None  # c3 appears in no dependency edge


def test_reingest_same_content_is_idempotent(client):
    first = _post(client, SBOM)
    second = _post(client, SBOM)
    assert first.status_code == 201
    assert second.status_code == 200
    assert second.json()["status"] == "duplicate"
    assert second.json()["receipt"]["counts"]["components_received"] == 3


def test_reingest_different_content_appends_new_receipt(client):
    changed = json.loads(json.dumps(SBOM))
    changed["components"][0]["version"] = "2.32.4"
    first = _post(client, SBOM)
    second = _post(client, changed)
    assert first.status_code == 201 and second.status_code == 201
    listed = client.get("/api/v1/components",
                        params={"project": "poc-fixture", "version": "0.1.0"},
                        headers={"X-API-Key": client.key})
    rows = listed.json()["data"]
    assert len(rows) == 3  # same identity set, version field updated in place
    versions = {row["identity_key"]: row["version"] for row in rows}
    assert versions["pkg:pypi/requests@2.32.3"] == "2.32.4"


def test_invalid_document_rejected(client):
    response = _post(client, {"bomFormat": "SPDX", "specVersion": "1.5"})
    assert response.status_code == 422
    response = _post(client, {"bomFormat": "CycloneDX", "specVersion": "1.5",
                              "components": []})
    assert response.status_code == 422  # missing metadata.component.name


def test_projects_listing(client):
    _post(client, SBOM)
    response = client.get("/api/v1/projects", headers={"X-API-Key": client.key})
    assert response.status_code == 200
    projects = response.json()["data"]
    assert len(projects) == 1
    assert projects[0]["name"] == "poc-fixture"
    assert projects[0]["versions"] == ["0.1.0"]


def test_unknown_project_version_404(client):
    response = client.get("/api/v1/components",
                          params={"project": "missing", "version": "1.0"},
                          headers={"X-API-Key": client.key})
    assert response.status_code == 404

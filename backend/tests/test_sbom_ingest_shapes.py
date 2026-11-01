"""SBOM ingest tolerates the shapes real scanners emit.

Regression cover for two live failures: syft lists the same component once per
manifest, and an iOS app produces an SBOM with no `components` key at all. The
first violated uq(project_version_id, component_id); the second was rejected
outright.
"""
import json
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/sbom.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "sbom")
    yield TestClient(app), {"X-API-Key": key}, session
    session.close()


def upload(client, headers, document, project, version="1.0.0"):
    return client.post(
        f"/api/v1/sbom?project={project}&version={version}&source=cli",
        content=json.dumps(document).encode(),
        headers={**headers, "Content-Type": "application/octet-stream"})


def document(components):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {"component": {"name": "app", "version": "1.0.0"}},
        "components": components,
    }


def test_repeated_component_links_once(client):
    client_, headers, session = client
    same = {"name": "lodash", "version": "4.17.21",
            "purl": "pkg:npm/lodash@4.17.21",
            "licenses": [{"license": {"id": "MIT"}}]}
    response = upload(client_, headers, document([same, dict(same), dict(same)]), "repeated")

    assert response.status_code == 201, response.text
    receipt = response.json()["receipt"]["counts"]
    assert receipt["components_received"] == 3
    assert receipt["components_created"] == 1
    assert receipt["links_created"] == 1

    links = session.query(models.VersionComponent).count()
    assert links == 1
    assert session.query(models.ComponentLicense).count() == 1


def test_sbom_without_components_is_accepted(client):
    client_, headers, _ = client
    response = upload(client_, headers, {"bomFormat": "CycloneDX", "specVersion": "1.5",
                                        "metadata": {"component": {"name": "app",
                                                                   "version": "1.0.0"}}},
                      "saria-ios")
    assert response.status_code == 201, response.text
    assert response.json()["receipt"]["counts"]["components_received"] == 0

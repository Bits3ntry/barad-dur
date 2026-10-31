"""BL-025 acceptance: SPDX 2.3 export."""
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

SBOM = {
    "bomFormat": "CycloneDX", "specVersion": "1.5",
    "serialNumber": "urn:uuid:aaaa-bbbb-cccc-dddd",
    "metadata": {"component": {"type": "application", "name": "spdx-app"}},
    "components": [
        {"type": "library", "name": "requests", "version": "2.32.3",
         "purl": "pkg:pypi/requests@2.32.3",
         "licenses": [{"license": {"id": "Apache-2.0"}}]},
        {"type": "library", "name": "libnoc", "version": "0.4",
         "licenses": []},
    ],
    "dependencies": [],
}


@pytest.fixture()
def spdx_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/spdx.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "spdx")
    session.add(models.Project(org_id=org.id, slug="spdx-app", name="spdx-app"))
    session.flush()
    session.add(models.ProjectVersion(
        project_id=session.query(models.Project).first().id, version="1.0"))
    session.commit()
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key})


def test_spdx_export_document(spdx_client):
    test_client, headers = spdx_client
    ingest = test_client.post(
        "/api/v1/sbom?project=spdx-app&version=1.0",
        content=json.dumps(SBOM).encode(),
        headers={**headers, "Content-Type": "application/octet-stream"})
    assert ingest.status_code in (200, 201)

    doc = test_client.get(
        "/api/v1/spdx/export?project=spdx-app&version=1.0",
        headers=headers).json()
    assert doc["spdxVersion"] == "SPDX-2.3"
    assert doc["SPDXID"] == "SPDXRef-DOCUMENT"
    assert doc["name"] == "spdx-app@1.0"
    assert len(doc["packages"]) == 2
    by_name = {pkg["name"]: pkg for pkg in doc["packages"]}
    assert by_name["requests"]["versionInfo"] == "2.32.3"
    assert by_name["requests"]["licenseDeclared"] == "Apache-2.0"
    assert by_name["requests"]["externalRefs"][0]["referenceLocator"] == \
        "pkg:pypi/requests@2.32.3"
    assert by_name["libnoc"]["licenseDeclared"] == "NOASSERTION"
    assert len(doc["relationships"]) == 2
    assert all(rel["relationshipType"] == "DESCRIBES" for rel in doc["relationships"])


def test_spdx_export_unknown_version(spdx_client):
    test_client, headers = spdx_client
    missing = test_client.get(
        "/api/v1/spdx/export?project=spdx-app&version=9.9", headers=headers)
    assert missing.status_code == 404

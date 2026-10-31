"""SPDX ingest and component diff between versions."""
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

SPDX = {
    "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT", "name": "payments-service",
    "creationInfo": {"creators": ["Tool: syft-1.0"], "created": "2026-10-31T00:00:00Z"},
    "packages": [
        {"SPDXID": "SPDXRef-Package-requests", "name": "requests",
         "versionInfo": "2.31.0", "licenseDeclared": "Apache-2.0",
         "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                           "referenceType": "purl",
                           "referenceLocator": "pkg:pypi/requests@2.31.0"}]},
        {"SPDXID": "SPDXRef-Package-urllib3", "name": "urllib3",
         "versionInfo": "1.26.5", "licenseDeclared": "MIT",
         "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                           "referenceType": "purl",
                           "referenceLocator": "pkg:pypi/urllib3@1.26.5"}]},
        {"SPDXID": "SPDXRef-Package-unknown", "name": "internal-lib",
         "versionInfo": "NOASSERTION", "licenseDeclared": "NOASSERTION"},
    ],
}

SPDX_V2 = json.loads(json.dumps(SPDX))
SPDX_V2["packages"] = [
    {"name": "requests", "versionInfo": "2.32.3", "licenseDeclared": "Apache-2.0",
     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                       "referenceType": "purl",
                       "referenceLocator": "pkg:pypi/requests@2.32.3"}]},
    {"name": "urllib3", "versionInfo": "1.26.5", "licenseDeclared": "MIT"},
    {"name": "certifi", "versionInfo": "2024.2.2", "licenseDeclared": "MPL-2.0"},
]


@pytest.fixture()
def spdx_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/spdxin.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    key = create_key(session, org.id, "spdxin")
    other_key = create_key(session, other.id, "spdxin2")
    session.commit()
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key}, {"X-API-Key": other_key})


def _import(test_client, headers, document, version):
    return test_client.post(
        "/api/v1/spdx/import",
        params={"project": "payments-service", "version": version},
        content=json.dumps(document).encode(),
        headers={**headers, "Content-Type": "application/json"})


def test_spdx_import_creates_components(spdx_client):
    test_client, headers, _other = spdx_client
    first = _import(test_client, headers, SPDX, "1.0")
    assert first.status_code in (200, 201), first.text
    receipt = first.json()
    assert receipt["receipt"]["counts"]["components_received"] == 3
    assert receipt["receipt"]["counts"]["components_created"] == 3

    components = test_client.get(
        "/api/v1/components?project=payments-service&version=1.0",
        headers=headers).json()["data"]
    by_name = {row["name"]: row for row in components}
    assert by_name["requests"]["version"] == "2.31.0"
    assert by_name["requests"]["purl"] == "pkg:pypi/requests@2.31.0"
    # NOASSERTION version is stored as unknown, not invented
    assert by_name["internal-lib"]["version"] in (None, "")

    # idempotent: the second import is a duplicate receipt, not new rows
    again = _import(test_client, headers, SPDX, "1.0")
    assert again.status_code in (200, 201)
    assert again.json()["status"] == "duplicate"
    assert again.json()["receipt"]["counts"]["components_created"] == \
        receipt["receipt"]["counts"]["components_created"]
    same = test_client.get("/api/v1/components?project=payments-service&version=1.0",
                           headers=headers).json()["data"]
    assert len(same) == 3

    # licenses landed through the same pipeline
    licenses = test_client.get("/api/v1/license-inventory?project=payments-service&version=1.0",
                               headers=headers).json()
    assert licenses.get("total", 0) >= 2  # licenses came through the same pipeline


def test_spdx_import_rejects_non_spdx(spdx_client):
    test_client, headers, _other = spdx_client
    bad = _import(test_client, headers, {"bomFormat": "CycloneDX"}, "1.0")
    assert bad.status_code == 422
    assert "SPDX" in bad.json()["detail"]


def test_sbom_compare_between_versions(spdx_client):
    test_client, headers, _other = spdx_client
    _import(test_client, headers, SPDX, "1.0")
    _import(test_client, headers, SPDX_V2, "2.0")
    diff = test_client.get("/api/v1/sbom/compare", params={
        "project": "payments-service", "from_version": "1.0",
        "to_version": "2.0"}, headers=headers).json()["data"]
    assert diff["counts"]["from"] == 3
    assert diff["counts"]["to"] == 3
    names_added = [row["name"] for row in diff["added"]]
    names_removed = [row["name"] for row in diff["removed"]]
    assert "certifi" in names_added
    assert "internal-lib" in names_removed
    changed = {row["name"]: row for row in diff["changed"]}
    assert changed["requests"]["from"] == "2.31.0"
    assert changed["requests"]["to"] == "2.32.3"
    assert "urllib3" not in changed  # unchanged stays quiet

    missing = test_client.get("/api/v1/sbom/compare", params={
        "project": "payments-service", "from_version": "1.0",
        "to_version": "9.9"}, headers=headers)
    assert missing.status_code == 404


def test_spdx_tenant_isolation(spdx_client):
    test_client, headers, other_headers = spdx_client
    _import(test_client, headers, SPDX, "1.0")
    foreign = test_client.get("/api/v1/components?project=payments-service&version=1.0",
                              headers=other_headers)
    assert foreign.status_code == 404  # the project does not exist in that org
    blocked = test_client.get("/api/v1/sbom/compare", params={
        "project": "payments-service", "from_version": "1.0",
        "to_version": "1.0"}, headers=other_headers)
    assert blocked.status_code == 404

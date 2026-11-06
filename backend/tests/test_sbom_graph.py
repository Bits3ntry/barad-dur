"""The dependency graph a BOM carries, as the platform should read it.

Trivy hangs the real packages off the file it scanned ("requirements.txt", type
application, no purl, no version). That node is a manifest, not a package, and
the platform has to walk through it instead of stopping at it — otherwise every
package ends up with no parent and not marked direct either.
"""
import json
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app.auth import create_key  # noqa: E402
from backend.app import models  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


def _document(deps, extra_metadata=None, version="1.0.0"):
    metadata = {"component": {"name": "container-fixture", "version": version,
                              "bom-ref": "root", "type": "application"}}
    metadata.update(extra_metadata or {})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": metadata,
        "components": [
            {"name": "requirements.txt", "bom-ref": "manifest", "type": "application"},
            {"name": "flask", "version": "3.0.0", "bom-ref": "pkg-flask",
             "purl": "pkg:pypi/flask@3.0.0"},
            {"name": "click", "version": "8.1.0", "bom-ref": "pkg-click",
             "purl": "pkg:pypi/click@8.1.0"},
        ],
        "dependencies": deps,
    }


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/graph-test.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="graph", name="Graph")
    session.add(org)
    session.flush()
    raw_key = create_key(session, org.id, "graph-key")
    session.close()
    from fastapi.testclient import TestClient

    test_client = TestClient(app)
    test_client.key = raw_key
    return test_client


def _post(client, doc, **params):
    return client.post("/api/v1/sbom", content=json.dumps(doc).encode(),
                       headers={"X-API-Key": client.key}, params=params)


def _rows(client, version="1.0.0"):
    response = client.get("/api/v1/components",
                          params={"project": "container-fixture", "version": version},
                          headers={"X-API-Key": client.key})
    assert response.status_code == 200, response.text
    return {row["name"]: row for row in response.json()["data"]}


def test_the_scanned_manifest_is_a_container_not_a_package(client):
    doc = _document([
        {"ref": "root", "dependsOn": ["manifest"]},
        {"ref": "manifest", "dependsOn": ["pkg-flask", "pkg-click"]},
    ])
    assert _post(client, doc).status_code == 201

    rows = _rows(client)
    # requirements.txt documents provenance; it is not software the build ships.
    assert set(rows) == {"flask", "click"}
    for row in rows.values():
        # Hanging off the manifest means direct: pip cannot tell us otherwise.
        assert row["is_direct"] is True
        assert row["parent_purl"] is None
        assert row["manifest_path"] == "requirements.txt"


def test_a_package_hanging_off_a_package_keeps_its_parent(client):
    doc = _document([
        {"ref": "root", "dependsOn": ["manifest", "pkg-flask"]},
        {"ref": "manifest", "dependsOn": ["pkg-flask"]},
        {"ref": "pkg-flask", "dependsOn": ["pkg-click"]},
    ])
    assert _post(client, doc).status_code == 201

    rows = _rows(client)
    assert rows["flask"]["is_direct"] is True
    assert rows["click"]["is_direct"] is False
    assert rows["click"]["parent_purl"] == "pkg:pypi/flask@3.0.0"


def test_reingesting_a_bom_with_edges_repairs_a_flat_link(client):
    flat = _document([])
    assert _post(client, flat).status_code == 201
    assert _rows(client)["click"]["parent_purl"] is None

    # Same project version, different bytes: the tree arrives late.
    with_edges = _document([
        {"ref": "root", "dependsOn": ["manifest"]},
        {"ref": "manifest", "dependsOn": ["pkg-flask"]},
        {"ref": "pkg-flask", "dependsOn": ["pkg-click"]},
    ], extra_metadata={"timestamp": "2026-11-05T10:00:00Z"})
    assert _post(client, with_edges).status_code == 201

    rows = _rows(client)
    assert rows["click"]["parent_purl"] == "pkg:pypi/flask@3.0.0"


def test_the_drawer_says_which_package_dragged_this_one_in(client):
    """"I have a CVE in click" is only actionable as "it came in through flask"."""
    doc = _document([
        {"ref": "root", "dependsOn": ["manifest"]},
        {"ref": "manifest", "dependsOn": ["pkg-flask"]},
        {"ref": "pkg-flask", "dependsOn": ["pkg-click"]},
    ])
    assert _post(client, doc).status_code == 201

    version = client.get("/api/v1/sbom/version",
                         params={"project": "container-fixture", "version": "1.0.0"},
                         headers={"X-API-Key": client.key}).json()["data"]
    click = next(row for row in version["component_rows"] if row["name"] == "click")
    assert click["parent_purl"] == "pkg:pypi/flask@3.0.0"

    detail = client.get("/api/v1/sbom/component",
                        params={"version_id": version["version_id"],
                                "component_id": click["component_id"]},
                        headers={"X-API-Key": client.key}).json()["data"]
    assert [hop["name"] for hop in detail["path"]] == ["flask"]

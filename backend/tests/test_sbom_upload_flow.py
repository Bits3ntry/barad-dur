"""The hand-delivered SBOM: detection, correction, and the same build a pipeline makes.

A pipeline inherits the project and the component from the repository it builds.
A person uploading a file has neither, and a Trivy document names its root `.`
(the scanned tree), so the platform has to guess, say why, and let the operator
correct the guess without inventing a component behind their back.
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


def _document(root_name, root_version=None, components=None):
    root = {"name": root_name, "type": "application"}
    if root_version:
        root["version"] = root_version
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": root},
        "components": components if components is not None else [
            {"name": "lodash", "version": "4.17.21",
             "purl": "pkg:npm/lodash@4.17.21", "bom-ref": "lodash"},
        ],
    }


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/upload.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "upload")
    project = models.Project(org_id=org.id, name="AUREA", slug="aurea")
    session.add(project)
    session.flush()
    for name, kind in (("Backend", "backend"), ("Frontend", "frontend")):
        session.add(models.ApplicationComponent(
            org_id=org.id, project_id=project.id, name=name,
            slug=name.lower(), kind=kind))
    session.commit()
    yield TestClient(app), {"X-API-Key": key}, session, org
    session.close()


def analyze(test_client, headers, document, filename=None):
    params = f"?filename={filename}" if filename else ""
    return test_client.post(f"/api/v1/sbom/analyze{params}",
                            content=json.dumps(document).encode(),
                            headers={**headers,
                                     "Content-Type": "application/octet-stream"})


def upload(test_client, headers, document, query):
    return test_client.post(f"/api/v1/sbom?{query}",
                            content=json.dumps(document).encode(),
                            headers={**headers,
                                     "Content-Type": "application/octet-stream"})


def test_analyze_names_the_project_from_the_root_component(client):
    test_client, headers, _session, _org = client
    response = analyze(test_client, headers, _document("aurea", "1.2.3"))
    assert response.status_code == 200, response.text
    data = response.json()["data"]
    assert data["detected"]["project"]["slug"] == "aurea"
    assert data["detected"]["project"]["reason"] == "project-slug"
    assert data["counts"]["components"] == 1
    assert data["format"]["spec_version"] == "1.6"


def test_analyze_detects_the_component_the_root_names(client):
    test_client, headers, _session, _org = client
    response = analyze(test_client, headers, _document("backend", "1.2.3"))
    data = response.json()["data"]
    assert data["detected"]["project"]["slug"] == "aurea"
    assert data["detected"]["component"]["slug"] == "backend"
    assert data["detected"]["component"]["reason"] == "component-slug"


def test_analyze_admits_when_the_document_names_nothing(client):
    """Trivy writes `.` as the root: the honest answer is "pick one"."""
    test_client, headers, _session, _org = client
    data = analyze(test_client, headers, _document(".", None)).json()["data"]
    assert data["detected"]["project"] is None
    assert data["detected"]["component"] is None
    assert "root_names_nothing" in data["warnings"]
    assert "project_not_detected" in data["warnings"]
    assert "version_missing" in data["warnings"]


def test_analyze_reads_the_version_out_of_the_filename(client):
    test_client, headers, _session, _org = client
    data = analyze(test_client, headers, _document(".", None),
                   filename="aurea-frontend-1.7.4.cdx.json").json()["data"]
    # The file name names the project, the version comes from its own stem, and
    # `frontend` is one of the project's components — which is the whole signal a
    # Trivy artifact leaves behind.
    assert data["detected"]["project"]["slug"] == "aurea"
    assert data["detected"]["project"]["reason"] == "filename"
    assert data["detected"]["component"]["slug"] == "frontend"
    assert data["detected"]["version"] == "1.7.4"
    assert data["detected"]["version_from"] == "filename"


def test_analyze_reports_the_identical_document_as_already_imported(client):
    test_client, headers, _session, _org = client
    document = _document("aurea", "1.2.3")
    first = upload(test_client, headers, document, "project=aurea&version=1.2.3&source=web")
    assert first.status_code == 201, first.text
    data = analyze(test_client, headers, document).json()["data"]
    assert data["duplicate"]["import_id"] == first.json()["import_id"]


def test_upload_creates_the_component_the_operator_named(client):
    test_client, headers, session, org = client
    document = _document(".", "1.0.0")
    refused = upload(test_client, headers, document,
                     "project=aurea&version=1.0.0&component=workers&source=web")
    assert refused.status_code == 422, refused.text
    assert "component not found" in refused.text

    created = upload(test_client, headers, document,
                     "project=aurea&version=1.0.0&component=workers"
                     "&create_component=true&source=web")
    assert created.status_code == 201, created.text
    row = (session.query(models.ApplicationComponent)
           .filter_by(org_id=org.id, slug="workers").one_or_none())
    assert row is not None
    version = (session.query(models.ProjectVersion)
               .filter_by(component_id=row.id, version="1.0.0").one_or_none())
    assert version is not None


def test_upload_answers_where_the_build_landed(client):
    test_client, headers, _session, _org = client
    response = upload(test_client, headers, _document("aurea", "2.0.0"),
                      "project=aurea&version=2.0.0&component=backend&source=web")
    assert response.status_code == 201, response.text
    build = response.json()["build"]
    assert build["project"] == "aurea"
    assert build["component"] == "backend"
    assert build["version"] == "2.0.0"
    assert build["version_id"]


def test_a_manual_upload_is_the_same_build_a_pipeline_makes(client):
    """Same rows, same counters, and no code weaknesses: only the source differs."""
    test_client, headers, session, org = client
    response = upload(test_client, headers, _document(".", "3.0.0"),
                      "project=aurea&version=3.0.0&component=backend&source=web")
    assert response.status_code == 201, response.text
    receipt = session.get(models.SbomImport, response.json()["import_id"])
    assert receipt.source == "web"
    assert receipt.components_received == 1
    version = session.get(models.ProjectVersion, receipt.project_version_id)
    assert version.component_id
    # An SBOM carries dependencies and their advisories; a code weakness needs a
    # source scan, so this build has none to show.
    assert session.query(models.Finding).filter_by(
        last_seen_version_id=version.id, kind="sast").count() == 0

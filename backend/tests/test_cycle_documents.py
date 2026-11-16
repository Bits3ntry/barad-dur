"""A cycle keeps its documents: the scope letter, the pentest report, the brief.

The bytes live with the cycle rather than behind a link, because the review is
written from the document, and a URL that rots takes the evidence with it.
"""
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
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/docs.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "docs")
    session.commit()
    from fastapi.testclient import TestClient

    return TestClient(app), {"X-API-Key": key}, session, org


def _cycle(client, headers, notes=None):
    body = {"name": "Pentest externo Q4", "kind": "pentest_external",
            "selection": {"whole_org": True}, "actor": "santiago"}
    if notes is not None:
        body["notes"] = notes
    return client.post("/api/v1/cycles", json=body, headers=headers).json()["data"]


def test_the_cycle_carries_its_notes(env):
    client, headers, _session, _org = env
    cycle = _cycle(client, headers, notes="El cliente excluye staging.")
    detail = client.get(f"/api/v1/cycles/{cycle['id']}", headers=headers).json()["data"]
    assert detail["notes"] == "El cliente excluye staging."


def test_a_document_round_trips_through_the_cycle(env):
    client, headers, _session, _org = env
    cycle = _cycle(client, headers)
    payload = b"%PDF-1.4 fake report bytes"
    uploaded = client.post(f"/api/v1/cycles/{cycle['id']}/documents",
                           params={"filename": "informe.pdf",
                                   "media_type": "application/pdf",
                                   "actor": "santiago"},
                           content=payload, headers=headers)
    assert uploaded.status_code == 201, uploaded.text
    document = uploaded.json()["data"]
    assert document["filename"] == "informe.pdf"
    assert document["size"] == len(payload)

    listing = client.get(f"/api/v1/cycles/{cycle['id']}/documents",
                         headers=headers).json()
    assert listing["total"] == 1
    assert listing["data"][0]["media_type"] == "application/pdf"

    downloaded = client.get(
        f"/api/v1/cycles/{cycle['id']}/documents/{document['id']}", headers=headers)
    assert downloaded.status_code == 200
    assert downloaded.content == payload
    assert "informe.pdf" in downloaded.headers["content-disposition"]


def test_an_empty_upload_is_refused_and_a_removed_one_is_gone(env):
    client, headers, _session, _org = env
    cycle = _cycle(client, headers)
    empty = client.post(f"/api/v1/cycles/{cycle['id']}/documents",
                        params={"filename": "vacio.pdf"}, content=b"", headers=headers)
    assert empty.status_code == 422

    uploaded = client.post(f"/api/v1/cycles/{cycle['id']}/documents",
                           params={"filename": "brief.txt"}, content=b"hola",
                           headers=headers).json()["data"]
    removed = client.delete(
        f"/api/v1/cycles/{cycle['id']}/documents/{uploaded['id']}", headers=headers)
    assert removed.status_code == 200
    again = client.get(f"/api/v1/cycles/{cycle['id']}/documents/{uploaded['id']}",
                       headers=headers)
    assert again.status_code == 404


def test_a_document_belongs_to_exactly_one_cycle(env):
    client, headers, _session, _org = env
    first = _cycle(client, headers)
    second = client.post("/api/v1/cycles", json={
        "name": "Otro", "selection": {"whole_org": True}}, headers=headers).json()["data"]
    document = client.post(f"/api/v1/cycles/{first['id']}/documents",
                           params={"filename": "scope.pdf"}, content=b"x",
                           headers=headers).json()["data"]
    crossed = client.get(f"/api/v1/cycles/{second['id']}/documents/{document['id']}",
                         headers=headers)
    assert crossed.status_code == 404

"""The finding page reads the detail endpoint, so the detail must be whole.

The detail used to keep its own copy of the payload and had drifted from the list:
no priority, no SLA, no build, no CVSS, no component name or version. The page is
built on exactly those fields, which is why "open a finding" showed a header and
nothing else. One shape, one place.
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
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/finding-page.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "page")
    project = models.Project(org_id=org.id, slug="fixture", name="fixture")
    session.add(project)
    session.flush()
    session.add(models.ProjectVersion(project_id=project.id, version="1.0"))
    session.commit()
    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}, session, org, project


def _ingest(client, headers, findings):
    return client.post("/api/v1/findings/ingest?project=fixture&version=1.0",
                       headers=headers,
                       json={"schema": "barad-findings-v1", "tool": "trivy",
                             "findings": findings})


def test_the_detail_carries_what_the_page_renders(env):
    client, headers, session, org, project = env
    ingested = _ingest(client, headers, [
        {"kind": "code-weakness", "title": "tarfile traversal", "severity": "CRITICAL",
         "rule_id": "CVE-2007-4559", "path": "python:3.11-slim"},
        {"kind": "code-weakness", "title": "another one", "severity": "HIGH",
         "rule_id": "CVE-2000-0001", "path": "python:3.11-slim"},
    ])
    assert ingested.status_code == 200, ingested.text
    row = client.get("/api/v1/findings", headers=headers).json()["data"][0]

    detail = client.get(f"/api/v1/findings/{row['id']}", headers=headers).json()["data"]
    for field in ("priority", "sla_deadline", "last_seen_version_id", "component_id",
                  "component_name",
                  "component_version", "component_purl", "first_seen_at", "last_seen_at",
                  "triage_status", "evidence_level", "origin", "status_reason",
                  "cvss_score", "fixed_version", "project", "version"):
        assert field in detail, f"the page reads {field} and the detail omits it"
    assert detail["project"] == "fixture"
    assert detail["version"] == "1.0"

    # …and the build is a query the page can actually make.
    version = client.get(f"/api/v1/findings?version_id={detail['last_seen_version_id']}",
                         headers=headers).json()
    assert version["total"] == 2
    assert {item["rule_id"] for item in version["data"]} == {"CVE-2007-4559", "CVE-2000-0001"}


def test_comments_and_evidence_round_trip(env):
    """The page writes both, so both have to come back the same way."""
    client, headers, _, _, _ = env
    assert _ingest(client, headers, [
        {"kind": "code-weakness", "title": "tarfile", "severity": "HIGH",
         "rule_id": "CVE-2007-4559"},
    ]).status_code == 200
    row = client.get("/api/v1/findings", headers=headers).json()["data"][0]

    said = client.post(f"/api/v1/findings/{row['id']}/comments", headers=headers,
                       json={"author": "ana@acme.dev", "body": "checked on main"})
    assert said.status_code == 201, said.text
    comments = client.get(f"/api/v1/findings/{row['id']}/comments", headers=headers).json()
    assert [(c["author"], c["body"]) for c in comments["data"]] == [("ana@acme.dev", "checked on main")]

    evidence = "trivy image python:3.11-slim\nCVE-2007-4559 CRITICAL\n"
    added = client.post(f"/api/v1/findings/{row['id']}/attachments", headers=headers,
                        json={"name": "scan.txt", "media_type": "text/plain",
                              "content": evidence, "added_by": "ana@acme.dev"})
    assert added.status_code == 201, added.text
    # The list is metadata only: a screen that listed bytes would ship the file
    # to every reader of the queue.
    listed = client.get(f"/api/v1/findings/{row['id']}/attachments", headers=headers).json()
    assert listed["total"] == 1
    assert "content" not in listed["data"][0]
    assert listed["data"][0]["size_bytes"] == len(evidence.encode())
    assert listed["data"][0]["redaction_state"] == "unreviewed"

    body = client.get(f"/api/v1/findings/{row['id']}/attachments/{listed['data'][0]['id']}",
                      headers=headers).json()["data"]
    assert body["content"] == evidence

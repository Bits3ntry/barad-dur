"""Project hierarchy: group -> project -> version, and the accounting rule.

Group totals must count one version per project (the latest, or whichever the
console selects); summing every historical version double-counts components and
inflates findings.
"""
import datetime
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
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/groups.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "k")

    def project(slug, group, versions):
        row = models.Project(org_id=org.id, slug=slug, name=slug, group_name=group)
        session.add(row)
        session.flush()
        base = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        for index, version in enumerate(versions):
            session.add(models.ProjectVersion(
                project_id=row.id, version=version,
                created_at=base + datetime.timedelta(days=index)))
        return row

    api_project = project("api", "Aurea", ["1.0", "2.0"])   # 2.0 is the latest
    project("web", "Aurea", ["1.0"])
    project("blog", None, ["1.0"])
    session.commit()
    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}, session, api_project


def test_latest_version_is_flagged(client):
    http, headers, _session, _project = client
    rows = http.get("/api/v1/inventory/portfolio", headers=headers).json()["data"]
    by_pair = {(row["project"], row["version"]): row["is_latest"] for row in rows}
    assert by_pair[("api", "2.0")] is True
    assert by_pair[("api", "1.0")] is False
    assert by_pair[("web", "1.0")] is True


def test_groups_roll_up_one_version_per_project(client):
    http, headers, _session, _project = client
    body = http.get("/api/v1/inventory/portfolio", headers=headers).json()
    groups = {group["group"]: group for group in body["groups"]}
    assert set(groups) == {"Aurea", "ungrouped"}
    # api has two versions; the group counts 2 projects, not 3 versions
    assert groups["Aurea"]["projects_count"] == 2
    assert groups["Aurea"]["versions"] == 2
    assert body["totals"]["versions"] == 4
    assert body["latest_totals"]["versions"] == 3


def test_patch_assigns_and_clears_group(client):
    http, headers, _session, _project = client
    assert http.patch("/api/v1/projects/blog", json={"group": "Saria"},
                      headers=headers).status_code == 200
    listed = {row["slug"]: row for row in http.get("/api/v1/projects", headers=headers).json()["data"]}
    assert listed["blog"]["group"] == "Saria"

    assert http.patch("/api/v1/projects/blog", json={"group": None},
                      headers=headers).status_code == 200
    listed = {row["slug"]: row for row in http.get("/api/v1/projects", headers=headers).json()["data"]}
    assert listed["blog"]["group"] is None

    rows = http.get("/api/v1/inventory/portfolio", headers=headers).json()["data"]
    assert {row["group"] for row in rows if row["project"] == "blog"} == {"ungrouped"}


def test_patch_unknown_project_is_404(client):
    http, headers, _session, _project = client
    assert http.patch("/api/v1/projects/nope", json={"group": "X"},
                      headers=headers).status_code == 404

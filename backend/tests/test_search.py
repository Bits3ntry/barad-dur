"""Estate search: the grammar, the join from a package to its projects, and the
org boundary.

The contract under test is the one the topbar promises: `node:20` answers "which
projects ship that dependency", `domain:` answers by host, a CVE answers with the
advisory group the Vulnerabilities screen can open, and nothing leaks across
organizations. The parser is pure, so the grammar is checked without a database.
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
from backend.app.routers.search import parse_query  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/search.db")
    monkeypatch.setenv("BOOTSTRAP_TOKEN", "boot-secret")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    from fastapi.testclient import TestClient

    return TestClient(app), session


def _seed(session):
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "search")

    project = models.Project(org_id=org.id, name="Aurea", slug="aurea",
                             group_name="Bitsentry", owner="santiago")
    other = models.Project(org_id=org.id, name="Payments", slug="payments")
    session.add_all([project, other])
    session.flush()

    code = models.ApplicationComponent(org_id=org.id, project_id=project.id,
                                       kind="backend", name="Backend", slug="backend")
    session.add(code)
    session.flush()
    version = models.ProjectVersion(project_id=project.id, component_id=code.id,
                                    version="main")
    session.add(version)
    session.flush()

    node = models.Component(org_id=org.id, identity_key="pkg:npm/node@20.1.0",
                            name="node", version="20.1.0",
                            purl="pkg:npm/node@20.1.0")
    node22 = models.Component(org_id=org.id, identity_key="pkg:npm/node@22.4.1",
                              name="node", version="22.4.1",
                              purl="pkg:npm/node@22.4.1")
    lodash = models.Component(org_id=org.id, identity_key="pkg:npm/lodash@4.17.21",
                              name="lodash", version="4.17.21",
                              purl="pkg:npm/lodash@4.17.21")
    session.add_all([node, node22, lodash])
    session.flush()
    session.add_all([
        models.VersionComponent(project_version_id=version.id, component_id=node.id,
                                is_direct=True),
        models.VersionComponent(project_version_id=version.id, component_id=lodash.id),
    ])

    asset = models.Asset(org_id=org.id, type="domain", value="api.aurea.example",
                         source="manual", project_id=project.id,
                         classification_status="classified")
    session.add(asset)

    advisory = models.Vulnerability(source_id="GHSA-aaaa", source="osv",
                                    cve_id="CVE-2024-1234",
                                    title="Prototype pollution in lodash",
                                    severity="HIGH")
    session.add(advisory)
    session.flush()
    session.add(models.Finding(
        org_id=org.id, project_id=project.id, asset_id=asset.id,
        origin="scanner", triage_status="triaged", evidence_level="observed",
        exploit_state="none", kind="dependency-cve", vector="dependency-cve",
        fingerprint="fp-search-1", source="osv", title="lodash prototype pollution",
        detail="CVE-2024-1234 in lodash 4.17.21", severity="HIGH",
        component_id=lodash.id, vulnerability_id=advisory.id, status="open",
        last_seen_version_id=version.id))
    session.flush()

    # A second tenant with the same package: scoping is the whole point.
    foreign = models.Organization(slug="other", name="Other")
    session.add(foreign)
    session.flush()
    foreign_key = create_key(session, foreign.id, "other")
    foreign_project = models.Project(org_id=foreign.id, name="Secret", slug="secret")
    session.add(foreign_project)
    session.flush()
    session.add(models.Asset(org_id=foreign.id, type="domain", value="secret.example",
                             source="manual", project_id=foreign_project.id,
                             classification_status="classified"))
    session.commit()
    return key, foreign_key


def test_grammar_is_typed_and_dependencies_need_no_prefix():
    parsed = parse_query('node:20 severity:moderate type:asset project:aurea "exact phrase"')
    assert parsed.deps == [("node", "20")]
    assert parsed.severity == "MEDIUM"
    assert parsed.kinds == {"asset"}
    assert parsed.project == "aurea"
    assert parsed.text == ["exact phrase"]

    scoped = parse_query("@angular/core@17 dep:lodash@4.17.21")
    assert scoped.deps == [("@angular/core", "17"), ("lodash", "4.17.21")]

    # A URL is free text, never a dependency.
    assert parse_query("https://aurea.example/x").deps == []
    # A CVE id stays an advisory filter.
    assert parse_query("cve:CVE-2024-1234").cve == "CVE-2024-1234"


def test_dependency_search_returns_the_projects_and_the_build_link(client):
    http, session = client
    key, _ = _seed(session)
    headers = {"X-API-Key": key}

    body = http.get("/api/v1/search", params={"q": "node:20"}, headers=headers).json()
    groups = {group["kind"]: group for group in body["groups"]}
    assert groups["project"]["total"] == 1
    assert groups["project"]["items"][0]["slug"] == "aurea"
    component = groups["component"]["items"][0]
    assert component["title"] == "node"
    assert component["version"] == "20.1.0"
    # The exact build the console opens: project/application component/version.
    assert component["project_slug"] == "aurea"
    assert component["component"] == "backend"
    assert component["version_label"] == "main"
    assert component["version_id"]

    # 22 is another release line: not a hit for 20.
    body = http.get("/api/v1/search", params={"q": "node:22"}, headers=headers).json()
    assert body["total"] == 0


def test_domain_cve_and_type_filters(client):
    http, session = client
    key, _ = _seed(session)
    headers = {"X-API-Key": key}

    body = http.get("/api/v1/search", params={"q": "domain:api.aurea"}, headers=headers).json()
    groups = {group["kind"]: group for group in body["groups"]}
    assert groups["asset"]["items"][0]["title"] == "api.aurea.example"
    assert groups["asset"]["items"][0]["project_slug"] == "aurea"
    assert groups["project"]["items"][0]["slug"] == "aurea"

    body = http.get("/api/v1/search", params={"q": "CVE-2024-1234"}, headers=headers).json()
    groups = {group["kind"]: group for group in body["groups"]}
    advisory = groups["vulnerability"]["items"][0]
    assert advisory["id"] == "CVE-2024-1234"
    assert advisory["severity"] == "HIGH"
    assert advisory["findings"] == 1
    assert advisory["projects"] == [{"slug": "aurea", "name": "Aurea"}]
    finding = groups["finding"]["items"][0]
    assert finding["id"] and finding["cve"] == "CVE-2024-1234"

    body = http.get("/api/v1/search", params={"q": "type:asset api"}, headers=headers).json()
    assert [group["kind"] for group in body["groups"]] == ["asset"]


def test_search_never_crosses_the_org_boundary(client):
    http, session = client
    key, foreign_key = _seed(session)

    body = http.get("/api/v1/search", params={"q": "secret"},
                    headers={"X-API-Key": key}).json()
    assert body["total"] == 0

    body = http.get("/api/v1/search", params={"q": "secret"},
                    headers={"X-API-Key": foreign_key}).json()
    # By kind, not by position: a group index is an accident of the order the
    # endpoint happens to build them in, and adding `version` moved it.
    by_kind = {group["kind"]: group for group in body["groups"]}
    assert by_kind["asset"]["items"][0]["title"] == "secret.example"

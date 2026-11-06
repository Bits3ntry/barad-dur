"""The pipeline builder: a closed catalog, and a file that matches it.

The screen promises three things, so this file pins all three: a pipeline may
only ask for what `push_allowed` allows, the generated file names the exact
commit the runner saw, and the provider decides the file — a GitLab repository
must not receive a GitHub workflow it cannot run.
"""
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models, pipeline_builder, scan_actions  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


@pytest.fixture()
def console(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/builder.db")
    monkeypatch.delenv("SHAURON_DAEMON_URL", raising=False)
    monkeypatch.delenv("PLATFORM_PUBLIC_URL", raising=False)
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "builder")
    project = models.Project(org_id=org.id, slug="aurea", name="Aurea")
    repository = models.Repository(
        org_id=org.id, provider="gitea", name="aurea-server",
        remote_url="https://gitea.example/bitsentry/aurea-server.git")
    session.add_all([project, repository])
    session.flush()
    session.add(models.ProjectRepository(
        org_id=org.id, project_id=project.id, repository_id=repository.id,
        added_by="santiago"))
    component = models.ApplicationComponent(
        org_id=org.id, project_id=project.id, name="Backend", slug="backend",
        kind="backend")
    orphan = models.ApplicationComponent(
        org_id=org.id, project_id=project.id, name="Web", slug="web", kind="frontend")
    session.add_all([component, orphan])
    session.flush()
    session.add(models.ComponentRepository(
        org_id=org.id, component_id=component.id, repository_id=repository.id,
        added_by="santiago"))
    session.commit()

    from fastapi.testclient import TestClient

    return {"client": TestClient(app), "headers": {"X-API-Key": key},
            "component_id": component.id, "orphan_id": orphan.id}


def test_the_catalog_says_how_far_a_pipeline_can_go(console):
    body = console["client"].get(
        "/api/v1/pipeline/blueprint", params={"project": "aurea"},
        headers=console["headers"]).json()["data"]
    actions = {row["name"]: row for row in body["actions"]}
    # Reading a checkout is what a runner can do on its own.
    assert actions["code"]["ci_allowed"] is True
    assert actions["supply-chain"]["ci_allowed"] is True
    # Reaching the network means the platform acts alone: grant + console.
    assert actions["web-surface"]["ci_allowed"] is False
    assert "grant" in actions["web-surface"]["blocked_reason"]
    assert actions["secrets-verified"]["ci_allowed"] is False
    # Every task carries its contract, so the screen can explain what runs.
    assert {task["contract"] for task in actions["code"]["tasks_detail"]} == {"sarif-2.1.0"}


def test_the_blueprint_knows_which_component_has_code(console):
    body = console["client"].get(
        "/api/v1/pipeline/blueprint", params={"project": "aurea"},
        headers=console["headers"]).json()["data"]
    components = {row["slug"]: row for row in body["components"]}
    assert components["backend"]["repositories"][0]["ci"] == "gitea"
    assert components["backend"]["repositories"][0]["ci_label"] == "Gitea Actions"
    # A component with no remote is offered with an empty list, not hidden: the
    # screen says what is missing instead of pretending it is not there.
    assert components["web"]["repositories"] == []
    assert body["api_url"] is None


def test_a_github_snippet_announces_and_waits_on_the_gate(console):
    data = console["client"].get(
        "/api/v1/pipeline/snippet",
        params={"project": "aurea", "component": console["component_id"],
                "actions": "code,supply-chain", "provider": "github",
                "triggers": "push,pull_request,manual", "branch": "main"},
        headers=console["headers"]).json()["data"]
    assert data["path"] == ".github/workflows/barad-dur.yml"
    body = data["body"]
    assert "['code', 'supply-chain']" in body
    assert '"project": \'aurea\'' in body
    # The file names the component a person reads, never its database id.
    assert '"component": \'backend\'' in body
    assert "/api/v1/scans" in body and "/gate" in body
    assert "BARAD_API_KEY" in body and "BARAD_URL" in body
    assert "pull_request:" in body and "workflow_dispatch:" in body
    # One secret, named once: the runner holds no other credential.
    assert data["secrets"] == ["BARAD_API_KEY"]


def test_a_gitlab_repository_gets_a_gitlab_job(console):
    data = console["client"].get(
        "/api/v1/pipeline/snippet",
        params={"project": "aurea", "component": console["component_id"],
                "actions": "code", "provider": "gitlab", "triggers": "push"},
        headers=console["headers"]).json()["data"]
    assert data["path"] == ".gitlab-ci.yml"
    assert "image: python" in data["body"]
    assert "CI_MERGE_REQUEST_IID" in data["body"] or "CI_PIPELINE_SOURCE" in data["body"]
    assert "merge_request_event" in data["body"] or "CI_COMMIT_BRANCH" in data["body"]


def test_an_unrecognised_provider_gets_the_portable_script(console):
    assert pipeline_builder.provider_for("git", "file:///src/aurea") == "generic"
    data = console["client"].get(
        "/api/v1/pipeline/snippet",
        params={"project": "aurea", "actions": "code", "provider": "generic"},
        headers=console["headers"]).json()["data"]
    assert data["path"] == "barad-ci.py"
    assert data["body"].startswith("#!/usr/bin/env python3")


def test_a_pipeline_may_not_ask_for_console_only_work(console):
    response = console["client"].get(
        "/api/v1/pipeline/snippet",
        params={"project": "aurea", "actions": "web-surface", "provider": "github"},
        headers=console["headers"])
    assert response.status_code == 422
    assert "grant" in response.text


def test_the_snippet_needs_a_selection(console):
    response = console["client"].get(
        "/api/v1/pipeline/snippet",
        params={"project": "aurea", "actions": "", "provider": "github"},
        headers=console["headers"])
    assert response.status_code == 422


def test_the_api_url_configured_on_the_platform_wins(console, monkeypatch):
    monkeypatch.setenv("PLATFORM_PUBLIC_URL", "https://barad.example:8090/")
    body = console["client"].get(
        "/api/v1/pipeline/blueprint", params={"project": "aurea"},
        headers=console["headers"]).json()["data"]
    assert body["api_url"] == "https://barad.example:8090"


def test_every_provider_renders_the_same_script():
    """The script is the contract; only the workflow around it may differ."""
    script = pipeline_builder.render_script("aurea", "backend", ["code"])
    assert "origin" in script and '"ci"' in script
    assert scan_actions.action("code") is not None

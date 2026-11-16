"""Settings → Integrations answers "configured", "by whom" and never "with what".

The screen exists because an operator who sees `configured` without knowing
whether it came from the console or the install cannot change it. The rule that
needs a test is the other half: no credential ever leaves this endpoint, not even
masked — the presence of one is the fact, the value is not.
"""
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
from backend.app.secrets import seal  # noqa: E402


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/integrations.db")
    for name in ("JIRA_BASE_URL", "JIRA_TOKEN", "JIRA_EMAIL", "GITHUB_TOKEN",
                 "GITLAB_TOKEN", "SMTP_HOST", "SMTP_PASSWORD"):
        monkeypatch.delenv(name, raising=False)
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="org", name="Org")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "integrations")
    session.commit()
    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}, session, org


def test_every_block_names_its_source_and_leaks_no_credential(env):
    client, headers, session, org = env
    session.add(models.IntegrationConnection(
        org_id=org.id, kind="scm", provider="gitea", base_url="https://gitea.example",
        account="bitsentry", secret_cipher=seal(session, "a-real-token-value"),
        access="read", config=json.dumps({"default_branch": "main"})))
    session.add(models.IntegrationConnection(
        org_id=org.id, kind="tickets", provider="jira", base_url="https://acme.atlassian.net",
        account="bot@acme.dev", secret_cipher=seal(session, "jira-token-value"),
        access="read"))
    session.add(models.Repository(org_id=org.id, provider="gitea",
                                 name="acme/api", remote_url="https://gitea.example/acme/api"))
    session.commit()

    body = client.get("/api/v1/integrations", headers=headers).json()
    raw = json.dumps(body)
    assert "a-real-token-value" not in raw
    assert "jira-token-value" not in raw

    data = body["data"]
    states = {row["provider"]: row for row in data["connections"]}
    assert states["gitea"]["source"] == "saved"
    assert states["gitea"]["has_secret"] is True
    assert states["gitea"]["state"] == "unverified"
    # Jira answers from the saved connection here, and the panel has to say so:
    # the environment is empty, so `saved` is the only honest answer.
    assert data["jira"]["source"] == "saved"
    assert data["jira"]["base_url"] == "https://acme.atlassian.net"
    assert data["jira"]["token_present"] is True
    assert data["scm"]["repositories"] == 1
    assert data["scm"]["by_provider"] == {"gitea": 1}
    assert data["mail"]["configured"] is False
    assert data["mail"]["source"] == "none"


def test_the_environment_is_named_when_nothing_was_saved(env, monkeypatch):
    client, headers, _, _ = env
    monkeypatch.setenv("JIRA_BASE_URL", "https://env.atlassian.net")
    monkeypatch.setenv("JIRA_EMAIL", "env@acme.dev")
    monkeypatch.setenv("JIRA_TOKEN", "env-token")
    data = client.get("/api/v1/integrations", headers=headers).json()["data"]
    assert data["jira"]["source"] == "environment"
    assert data["jira"]["base_url"] == "https://env.atlassian.net"
    assert "env-token" not in json.dumps(data)
    # …and with nothing saved and nothing in the environment, the answer is
    # "none", not a blank that looks like a bug.
    monkeypatch.delenv("JIRA_TOKEN")
    data = client.get("/api/v1/integrations", headers=headers).json()["data"]
    assert data["jira"]["configured"] is False

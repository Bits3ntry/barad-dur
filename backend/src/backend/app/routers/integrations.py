"""Settings → Integrations: what this organisation is wired to, and how it stands.

One read for the four connections the platform actually makes outbound:

    scm      a code host (GitHub / GitLab / Gitea) — list, clone, analyse, never push
    tickets  Jira — findings out, workflow back
    mail     SMTP — invitations and alerts
    scanners the surface plane's own policy (grants + scope), not a credential

Two sources per connection, named in every answer: `saved` (in the console) or
`environment` (the install's env). An operator who sees "configured" without
knowing which of the two is answering cannot change it — that is the whole
reason this endpoint exists instead of four separate reads in four screens.

No credential is ever returned. For `scm` and `tickets` the row projection is
`onboarding._connection_data`, which is the one place that rule is written; for
mail only the non-secret half of the resolved configuration.
"""
from __future__ import annotations

import json
import os

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app import auth, integrations as integration_store, jira_client, mail, models
from backend.app.db import get_session
from backend.app.routers.onboarding import _connection_data

router = APIRouter(prefix="/api/v1/integrations", tags=["integrations"])

ENVIRONMENT = {
    "jira": {"base_url": "JIRA_BASE_URL", "account": "JIRA_EMAIL", "token": "JIRA_TOKEN"},
    "github": {"token": "GITHUB_TOKEN", "base_url": "GITHUB_API_URL"},
    "gitlab": {"token": "GITLAB_TOKEN", "base_url": "GITLAB_API_URL"},
    "gitea": {"token": "GITEA_TOKEN", "base_url": "GITEA_URL"},
}


def _env_state(provider: str) -> dict:
    """What the environment provides, by presence — never by value."""
    keys = ENVIRONMENT.get(provider) or {}
    present = {name: bool(os.environ.get(key)) for name, key in keys.items()}
    return {"base_url": os.environ.get(keys.get("base_url", ""), "") or None,
            "account": os.environ.get(keys.get("account", ""), "") or None,
            "token_present": present.get("token", False)}


def _connection_state(row: models.IntegrationConnection) -> str:
    if row.last_error:
        return "error"
    if row.verified_at:
        return "verified"
    return "unverified"


@router.get("")
def integrations_overview(org: models.Organization = Depends(auth.require_admin),
                          session: Session = Depends(get_session)):
    """Everything wired, with the source of every answer."""
    rows = (session.query(models.IntegrationConnection)
            .filter_by(org_id=org.id)
            .order_by(models.IntegrationConnection.kind,
                      models.IntegrationConnection.provider).all())
    connections = []
    for row in rows:
        data = _connection_data(row)
        # The credential is the one thing this screen must not show; the fact
        # that one exists is what the operator actually needs.
        data["has_secret"] = bool(row.secret_cipher)
        data["state"] = _connection_state(row)
        data["source"] = "saved"
        connections.append(data)

    scm = [row for row in rows if row.kind == "scm"]
    tickets = [row for row in rows if row.kind == "tickets"]

    repositories = (session.query(models.Repository)
                    .filter_by(org_id=org.id).all())
    by_provider: dict[str, int] = {}
    for repository in repositories:
        by_provider[repository.provider] = by_provider.get(repository.provider, 0) + 1

    # Jira answers from the saved connection first and the environment second —
    # the same order `jira_client.config_for` uses, so this screen cannot claim a
    # connection that a send would not find.
    saved_ticket = integration_store.for_tickets(session, org.id)
    has_saved_token = bool((saved_ticket or {}).get("token"))
    try:
        base, account, token = jira_client.config_for(session, org.id)
        jira = {"configured": bool(token), "base_url": base or None,
                "account": account or None, "token_present": bool(token),
                # Which of the two answered: an operator who cannot change the
                # environment is looking at the wrong half of the answer.
                "source": "saved" if has_saved_token else "environment"}
    except jira_client.JiraError:
        jira = {"configured": False, "base_url": _env_state("jira")["base_url"],
                "account": None, "token_present": False, "source": "none"}

    links = session.query(models.JiraLink).filter_by(org_id=org.id).all()
    outbox = (session.query(models.JiraOutbox)
              .filter_by(org_id=org.id).all())
    jira["links"] = len(links)
    jira["linked"] = sum(1 for link in links if link.issue_key)
    jira["failed_links"] = sum(1 for link in links if link.last_error)
    jira["outbox_pending"] = sum(1 for item in outbox if item.status == "pending")
    jira["outbox_failed"] = sum(1 for item in outbox if item.status == "failed")
    jira["webhook_secret"] = bool(os.environ.get("JIRA_WEBHOOK_SECRET"))
    jira["project_keys"] = sorted({link.project_key for link in links if link.project_key})

    settings = mail.resolve(session)
    mail_block = {"configured": bool(settings.get("host")),
                  "host": settings.get("host") or None,
                  "port": settings.get("port"),
                  "sender": settings.get("sender") or None,
                  "user": settings.get("user") or None,
                  "source": settings.get("source") or "none",
                  # Which half is missing is the actionable part: a host without
                  # a password is a server that will refuse every send.
                  "has_password": bool(settings.get("configured_password")
                                       or os.environ.get("SMTP_PASSWORD")),
                  "starttls": bool(settings.get("starttls"))}

    return {"data": {
        "connections": connections,
        "scm": {"configured": bool(scm) or any(_env_state(name)["token_present"]
                                               for name in ("github", "gitlab", "gitea")),
                "connections": len(scm),
                "providers": sorted({row.provider for row in scm}
                                    | {name for name in ("github", "gitlab", "gitea")
                                       if _env_state(name)["token_present"]}),
                "repositories": len(repositories),
                "by_provider": by_provider,
                "environment": {name: _env_state(name)
                                for name in ("github", "gitlab", "gitea")}},
        "jira": jira,
        "mail": mail_block,
        "repositories": [
            {"name": repository.name, "provider": repository.provider,
             "remote_url": repository.remote_url,
             "last_commit_sha": repository.last_commit_sha}
            for repository in sorted(repositories, key=lambda row: row.name)],
    }}

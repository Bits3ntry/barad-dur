"""Credentials an organization registered in the console, resolved at call time.

An integration is a row in `integration_connections` (kind `scm` or `tickets`)
whose secret is sealed with the platform key. Runtime code asks this module for
the credential it needs instead of reading the environment:

    creds = integrations.for_scm(session, org.id, remote_url=repo.remote_url)

The environment stays as a fallback for deployments configured the old way, so
nothing that worked before stops working — but a saved connection always wins.

`None` means "no connection registered"; callers then decide whether the
environment fallback applies or the feature is simply not configured.
"""
import json

from sqlalchemy.orm import Session

from backend.app import models, secrets as secret_store


def _open(session: Session, row: models.IntegrationConnection) -> dict | None:
    try:
        token = secret_store.open_sealed(session, row.secret_cipher)
    except ValueError:
        # A rotated platform key makes the stored token unusable. Reporting the
        # connection as absent is honest; sending with no token is not.
        return None
    try:
        config = json.loads(row.config or "{}")
    except json.JSONDecodeError:
        config = {}
    return {"id": row.id, "kind": row.kind, "provider": row.provider,
            "base_url": row.base_url, "account": row.account, "token": token,
            "config": config, "access": row.access,
            "verified_at": row.verified_at.isoformat() if row.verified_at else None}


def find(session: Session, org_id: str, kind: str,
         provider: str | None = None, base_url: str | None = None) -> dict | None:
    query = (session.query(models.IntegrationConnection)
             .filter_by(org_id=org_id, kind=kind))
    if provider:
        query = query.filter_by(provider=provider)
    if base_url:
        query = query.filter_by(base_url=base_url)
    row = query.order_by(models.IntegrationConnection.created_at).first()
    return _open(session, row) if row is not None else None


def provider_from(remote_url: str | None) -> str | None:
    """github / gitlab / gitea, read from the remote host. None when unknown."""
    from backend.app import scm_client

    try:
        return scm_client.provider_for(remote_url or "")
    except scm_client.ScmError:
        return None


def for_scm(session: Session, org_id: str,
            remote_url: str | None = None,
            provider: str | None = None) -> dict | None:
    """The code host that can serve this repository (or the first one registered)."""
    wanted = provider or provider_from(remote_url)
    if wanted:
        found = find(session, org_id, "scm", provider=wanted)
        if found is not None:
            return found
    return find(session, org_id, "scm")


def for_tickets(session: Session, org_id: str,
                provider: str = "jira") -> dict | None:
    return find(session, org_id, "tickets", provider=provider)

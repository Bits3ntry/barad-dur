"""API-key authentication: X-API-Key header, SHA-256 lookup, org resolution."""
import hashlib
import secrets

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from backend.app import models
from backend.app.db import get_session

_MISSING = HTTPException(status.HTTP_401_UNAUTHORIZED, "missing or malformed API key")
_UNKNOWN = HTTPException(status.HTTP_401_UNAUTHORIZED, "unknown API key")


def key_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def generate_api_key() -> str:
    return secrets.token_hex(32)


def create_key(session: Session, org_id: str, label: str = "") -> str:
    """Store the hash of a freshly generated key; the raw value returns once."""
    raw = generate_api_key()
    session.add(models.ApiKey(org_id=org_id, key_hash=key_hash(raw), label=label))
    session.commit()
    return raw


def require_org(
    session: Session = Depends(get_session),
    x_api_key: str = Header(default="", alias="X-API-Key"),
) -> models.Organization:
    """FastAPI dependency: resolve the caller's organization or reject with 401.

    get_session is request-cached, so routers share this same session.
    """
    if not x_api_key or len(x_api_key) > 128:
        raise _MISSING
    row = session.query(models.ApiKey).filter_by(key_hash=key_hash(x_api_key)).one_or_none()
    if row is None or row.revoked_at is not None:
        raise _UNKNOWN
    org = session.get(models.Organization, row.org_id)
    if org is None:
        raise _UNKNOWN
    return org

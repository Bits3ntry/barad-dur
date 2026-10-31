"""Authentication: API keys (service identities) and user sessions.

Two credential kinds resolve to an organization:
  * `X-API-Key` — the org's service identity (CLI, CI, workers). Full org
    rights, exactly as before.
  * `Authorization: Bearer <session>` — a human user with a role.

RBAC is enforced here so no router can forget it: a `viewer` may only read
(safe methods), `analyst` may write operational data, and `admin`/`owner` are
required for identity, authorization and orchestration administration. API
keys bypass the role check by design: they are machine identities, and the
gate for their actions is the authorization engine (BL-015).
"""
import hashlib
import secrets

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from backend.app import models
from backend.app.db import get_session

_MISSING = HTTPException(status.HTTP_401_UNAUTHORIZED, "missing or malformed API key")
_UNKNOWN = HTTPException(status.HTTP_401_UNAUTHORIZED, "unknown API key")
_SESSION_INVALID = HTTPException(status.HTTP_401_UNAUTHORIZED,
                                 "invalid or expired session")

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2, "owner": 3}


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


def _session_principal(session: Session, raw_token: str) -> dict | None:
    from backend.app import auth_local

    row = (session.query(models.UserSession)
           .filter_by(token_hash=auth_local.token_hash(raw_token)).one_or_none())
    if row is None or row.revoked_at is not None:
        return None
    from backend.app import auth_local as _auth_local

    if _auth_local.ensure_aware(row.expires_at) <= models.utcnow():
        return None
    user = session.get(models.User, row.user_id)
    if user is None or user.status != "active":
        return None
    return {"org_id": user.org_id, "role": user.role, "user_id": user.id,
            "kind": "user", "email": user.email}


def resolve_principal(session: Session, x_api_key: str = "",
                      authorization: str = "") -> dict:
    """Resolve the caller to {org_id, role, kind}. Raises 401 otherwise."""
    if authorization.lower().startswith("bearer "):
        principal = _session_principal(session, authorization[7:].strip())
        if principal is None:
            raise _SESSION_INVALID
        return principal
    if not x_api_key or len(x_api_key) > 128:
        raise _MISSING
    row = (session.query(models.ApiKey)
           .filter_by(key_hash=key_hash(x_api_key)).one_or_none())
    if row is None or row.revoked_at is not None:
        raise _UNKNOWN
    return {"org_id": row.org_id, "role": "owner", "kind": "api_key",
            "user_id": None}


def _enforce(principal: dict, request: Request, minimum: str | None):
    if principal["kind"] == "api_key":
        return
    role = principal["role"]
    if minimum is None and request.method not in SAFE_METHODS and role == "viewer":
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "role 'viewer' is read-only")
    if minimum is not None and ROLE_RANK.get(role, -1) < ROLE_RANK[minimum]:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            f"role '{role}' cannot perform this action "
                            f"(requires {minimum})")


def _organization_from(principal, session):
    org = session.get(models.Organization, principal["org_id"])
    if org is None:
        raise _UNKNOWN
    return org


def require_org(
    request: Request,
    session: Session = Depends(get_session),
    x_api_key: str = Header(default="", alias="X-API-Key"),
    authorization: str = Header(default=""),
) -> models.Organization:
    """Resolve the caller's organization, enforcing the viewer write rule."""
    principal = resolve_principal(session, x_api_key, authorization)
    _enforce(principal, request, None)
    return _organization_from(principal, session)


def require_writer(
    request: Request,
    session: Session = Depends(get_session),
    x_api_key: str = Header(default="", alias="X-API-Key"),
    authorization: str = Header(default=""),
) -> models.Organization:
    principal = resolve_principal(session, x_api_key, authorization)
    _enforce(principal, request, "analyst")
    return _organization_from(principal, session)


def require_admin(
    request: Request,
    session: Session = Depends(get_session),
    x_api_key: str = Header(default="", alias="X-API-Key"),
    authorization: str = Header(default=""),
) -> models.Organization:
    principal = resolve_principal(session, x_api_key, authorization)
    _enforce(principal, request, "admin")
    return _organization_from(principal, session)

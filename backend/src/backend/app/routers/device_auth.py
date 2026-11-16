"""`shauron login`: a terminal becomes a session because a human said so.

Four calls and one table. The terminal asks for a code, the operator opens the
console with that code, signs in as they always do, and approves **that machine**.
The terminal then trades its secret for a real session — the same `UserSession`
the browser gets, so refresh, revocation and the audit trail are not a second
mechanism.

Why this shape and not a key pasted into a shell: a key is a bearer string that
outlives the terminal, prints in `ps`, and pastes into chat. A device code is
worthless without the secret that never leaves the machine, expires in eight
minutes, is bound to a hostname the approver can read, and produces a session that
can be revoked without rotating anything.
"""
from __future__ import annotations

import datetime
import hashlib
import os
import secrets
from typing import Literal

from fastapi import (APIRouter, Depends, Header, HTTPException, Request,
                     status)
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, auth_local, models
from backend.app.db import get_session
from backend.app.routers.accounts import _issue_session
from backend.app.routers.identity import _audit as _audit_log

public_router = APIRouter(prefix="/api/v1", tags=["device-auth"])
router = APIRouter(prefix="/api/v1", tags=["device-auth"])

# No vowels (so a code cannot spell a word) and no 0/O/1/I (so it cannot be
# mistyped from a screenshot).
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
CODE_TTL_S = 480
INTERVAL_S = 5


def _now() -> datetime.datetime:
    return models.utcnow()


def _aware(value: datetime.datetime | None) -> datetime.datetime | None:
    return auth_local.ensure_aware(value) if value is not None else None


def _expires_at(row: models.DeviceAuthorization) -> datetime.datetime:
    return _aware(row.expires_at) or _now()


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _user_code() -> str:
    raw = "".join(secrets.choice(ALPHABET) for _ in range(8))
    return f"{raw[:4]}-{raw[4:]}"


def _console_url() -> str:
    return (os.environ.get("PLATFORM_CONSOLE_URL")
            or os.environ.get("CONSOLE_URL") or "http://localhost:8092").rstrip("/")


class CodeIn(BaseModel):
    hostname: str | None = Field(default=None, max_length=128)
    platform: str | None = Field(default=None, max_length=64)
    agent: str | None = Field(default=None, max_length=64)


class TokenIn(BaseModel):
    device_code: str = Field(min_length=16, max_length=128)


class ApproveIn(BaseModel):
    user_code: str = Field(min_length=8, max_length=16)
    decision: Literal["approve", "deny"] = "approve"


def _normalise_code(raw: str) -> str:
    cleaned = "".join(character for character in raw.upper()
                      if character.isalnum())
    return f"{cleaned[:4]}-{cleaned[4:]}" if len(cleaned) == 8 else cleaned


@public_router.post("/auth/device/code", status_code=status.HTTP_201_CREATED)
def device_code(payload: CodeIn = None, session: Session = Depends(get_session)):
    """Open a request. Nothing is authorized yet — a human has to say yes."""
    payload = payload or CodeIn()
    device_code = secrets.token_urlsafe(32)
    row = models.DeviceAuthorization(
        user_code=_user_code(), device_code_hash=_hash(device_code),
        status="pending", hostname=payload.hostname, platform=payload.platform,
        agent=payload.agent, created_at=_now(),
        expires_at=_now() + datetime.timedelta(seconds=CODE_TTL_S))
    session.add(row)
    session.commit()
    return {"device_code": device_code, "user_code": row.user_code,
            "verification_uri": f"{_console_url()}/#activate::{row.user_code}",
            "expires_in": CODE_TTL_S, "interval": INTERVAL_S}


@public_router.post("/auth/device/token")
def device_token(payload: TokenIn = None, request: Request = None,
                 session: Session = Depends(get_session)):
    """Trade the secret for a session, or say precisely why you cannot.

    The error codes are the protocol: `authorization_pending` means keep waiting,
    `slow_down` means you are polling faster than told, `access_denied` means a
    human said no, `expired_token` means start over. Anything else is a bug.
    """
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    row = (session.query(models.DeviceAuthorization)
           .filter_by(device_code_hash=_hash(payload.device_code)).one_or_none())
    if row is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid_grant")
    if row.status == "consumed":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid_grant")
    if row.status == "pending" and _expires_at(row) <= _now():
        row.status = "expired"
        session.commit()
    if row.status == "expired" or _expires_at(row) <= _now():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "expired_token")
    if row.status == "denied":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "access_denied")
    # Rate limit before anything else: the interval is a rule for every poll, not
    # only for the waiting ones, or a client that retries in a loop gets faster
    # answers the closer it is to stealing a session.
    last = _aware(row.last_polled_at)
    row.polls += 1
    row.last_polled_at = _now()
    session.commit()
    if last is not None and (_now() - last).total_seconds() < INTERVAL_S - 1:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "slow_down")
    if row.status == "pending":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "authorization_pending")

    user = session.get(models.User, row.user_id) if row.user_id else None
    if user is None or user.status != "active":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "access_denied")
    issued = _issue_session(
        session, user,
        user_agent=f"shauron-cli/{row.agent or 'cli'} on {row.hostname or 'unknown'}")
    row.status = "consumed"
    row.consumed_at = _now()
    session.commit()
    org = session.get(models.Organization, user.org_id)
    return {**issued, "org": {"id": user.org_id,
                              "slug": getattr(org, "slug", None),
                              "name": getattr(org, "name", None)},
            "hostname": row.hostname}


def _approver(request: Request, session: Session,
              x_api_key: str = "", authorization: str = "",
              x_worker_token: str = ""):
    principal = auth.resolve_principal(session, x_api_key, authorization,
                                       x_worker_token)
    auth._enforce(principal, request, None)
    if principal["kind"] not in {"user", "api_key"} or \
            principal.get("role") not in {"owner", "admin"}:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "only an owner or an admin can approve a CLI login")
    return principal


@router.get("/auth/device/pending")
def device_pending(request: Request = None, session: Session = Depends(get_session),
                   x_api_key: str = Header(default="", alias="X-API-Key"),
                   authorization: str = Header(default=""),
                   x_worker_token: str = Header(default="", alias="X-Worker-Token")):
    """What is waiting for a decision, so the console can answer without a code."""
    principal = _approver(request, session, x_api_key, authorization, x_worker_token)
    rows = (session.query(models.DeviceAuthorization)
            .filter_by(status="pending")
            .order_by(models.DeviceAuthorization.created_at.desc())
            .limit(25).all())
    return {"pending": [{"user_code": row.user_code, "hostname": row.hostname,
                         "platform": row.platform, "agent": row.agent,
                         "requested_at": row.created_at.isoformat() if row.created_at else None,
                         "expires_at": row.expires_at.isoformat() if row.expires_at else None}
                        for row in rows if _expires_at(row) > _now()],
            "org": principal.get("org_id")}


@router.post("/auth/device/approve")
def device_approve(payload: ApproveIn = None, request: Request = None,
                   session: Session = Depends(get_session),
                   x_api_key: str = Header(default="", alias="X-API-Key"),
                   authorization: str = Header(default=""),
                   x_worker_token: str = Header(default="", alias="X-Worker-Token")):
    """A human answers for a machine. Owner or admin only, audited either way."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    principal = _approver(request, session, x_api_key, authorization, x_worker_token)
    row = (session.query(models.DeviceAuthorization)
           .filter_by(user_code=_normalise_code(payload.user_code)).one_or_none())
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "that code is not waiting")
    # Expiry is checked before the status, because a code that lapsed during a
    # poll is `expired` already — reporting it as "already expired" (409) hides
    # the one action that fixes it: ask for a new code.
    if _expires_at(row) <= _now() or row.status == "expired":
        row.status = "expired"
        session.commit()
        raise HTTPException(status.HTTP_410_GONE, "the code expired; run the login again")
    if row.status != "pending":
        raise HTTPException(status.HTTP_409_CONFLICT, f"this code is already {row.status}")

    actor = principal.get("email") or "api-key"
    if payload.decision == "deny":
        row.status = "denied"
        row.decided_by = actor
        row.decided_at = _now()
        session.commit()
        _audit_log(session, principal["org_id"], actor, "auth.device.denied",
                   "device", row.id, f"{row.hostname or 'unknown'} denied")
        return {"status": "denied", "hostname": row.hostname}

    if principal["kind"] == "api_key":
        # An API key is not a person: approving a session with it would mint a
        # human session out of a machine credential, which is how a leaked key
        # becomes an account.
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "sign in as a person to approve a CLI login")
    if principal.get("org_id") is None or principal.get("user_id") is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "no user behind this credential")

    row.status = "approved"
    row.org_id = principal["org_id"]
    row.user_id = principal["user_id"]
    row.decided_by = actor
    row.decided_at = _now()
    session.commit()
    _audit_log(session, principal["org_id"], actor, "auth.device.approved",
               "device", row.id, f"{row.hostname or 'unknown'} approved for the CLI")
    return {"status": "approved", "hostname": row.hostname,
            "user_code": row.user_code}

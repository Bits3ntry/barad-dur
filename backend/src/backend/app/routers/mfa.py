"""Optional second factor: TOTP enrolment, verification and recovery codes.

The second factor is per user and deliberately optional — an administrator
never gets to lock people out by enabling it on their behalf. Enrolment is a
two-step handshake (secret, then a code that proves the authenticator has it),
because a user who scans the QR and leaves has to remain able to log in.

Sessions are minted only after the challenge is solved; a correct password on a
user with MFA returns a short-lived challenge token, never a session.
"""
import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, auth_local, mfa, models
from backend.app.db import get_session
from backend.app.routers.accounts import _issue_session, _user_data
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1/auth", tags=["mfa"])

CHALLENGE_TTL_MINUTES = 5
MAX_ATTEMPTS = 5


class PasswordIn(BaseModel):
    password: str = Field(default="", max_length=255)
    actor: str | None = Field(default=None, max_length=255)


class CodeIn(BaseModel):
    code: str = Field(min_length=4, max_length=32)
    actor: str | None = Field(default=None, max_length=255)


class VerifyIn(BaseModel):
    challenge: str = Field(min_length=10, max_length=256)
    code: str = Field(min_length=4, max_length=32)


def _current_user(request: Request, session: Session,
                  x_api_key: str = Header(default="", alias="X-API-Key"),
                  authorization: str = Header(default="")) -> models.User:
    """MFA belongs to a human session; API keys are governed elsewhere."""
    principal = auth.resolve_principal(session, x_api_key, authorization)
    if principal["kind"] != "user" or not principal.get("user_id"):
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "multi-factor settings need a signed-in user")
    user = session.get(models.User, principal["user_id"])
    if user is None or user.status != "active":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "user disabled")
    return user


def _require_password(user: models.User, password: str | None) -> None:
    """Re-authenticate for the changes that weaken or replace the factor."""
    if user.password_hash and not auth_local.verify_password(user.password_hash,
                                                             password or ""):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "password required")


def _recovery_left(session: Session, user: models.User) -> int:
    return (session.query(models.MfaRecoveryCode)
            .filter_by(user_id=user.id, used_at=None).count())


def _status(session: Session, user: models.User) -> dict:
    return {
        "enabled": user.totp_enabled_at is not None,
        "enrolled_at": user.totp_enabled_at.isoformat() if user.totp_enabled_at else None,
        "pending": bool(user.totp_secret) and user.totp_enabled_at is None,
        "recovery_codes_left": _recovery_left(session, user),
    }


def _consume_recovery_code(session: Session, user: models.User, code: str) -> bool:
    digest = auth_local.token_hash(mfa.normalise_recovery_code(code))
    row = (session.query(models.MfaRecoveryCode)
           .filter_by(user_id=user.id, code_hash=digest, used_at=None).one_or_none())
    if row is None:
        return False
    row.used_at = models.utcnow()
    return True


def _verify_second_factor(session: Session, user: models.User, code: str) -> bool:
    if user.totp_secret and mfa.verify(user.totp_secret, code):
        return True
    return _consume_recovery_code(session, user, code)


def _replace_recovery_codes(session: Session, user: models.User) -> list[str]:
    for row in session.query(models.MfaRecoveryCode).filter_by(user_id=user.id,
                                                               used_at=None):
        row.used_at = models.utcnow()
    codes = mfa.generate_recovery_codes()
    now = models.utcnow()
    for code in codes:
        session.add(models.MfaRecoveryCode(
            org_id=user.org_id, user_id=user.id,
            code_hash=auth_local.token_hash(mfa.normalise_recovery_code(code)),
            created_at=now))
    return codes


@router.get("/mfa")
def mfa_status(request: Request,
               session: Session = Depends(get_session),
               x_api_key: str = Header(default="", alias="X-API-Key"),
               authorization: str = Header(default="")):
    user = _current_user(request, session, x_api_key, authorization)
    return {"data": _status(session, user)}


@router.post("/mfa/enroll")
def mfa_enroll(payload: PasswordIn = None, request: Request = None,
               session: Session = Depends(get_session),
               x_api_key: str = Header(default="", alias="X-API-Key"),
               authorization: str = Header(default="")):
    user = _current_user(request, session, x_api_key, authorization)
    _require_password(user, payload.password if payload else "")
    secret = mfa.generate_secret()
    user.totp_secret = secret
    user.totp_enabled_at = None
    user.updated_at = models.utcnow()
    session.commit()
    return {"data": {
        "secret": secret,
        "otpauth": mfa.provisioning_uri(secret, user.email),
        "digits": mfa.DIGITS,
        "period": mfa.STEP_SECONDS,
        "note": ("the factor is not active until a code from the authenticator "
                 "is confirmed; abandoning this screen leaves login unchanged"),
    }}


@router.post("/mfa/activate")
def mfa_activate(payload: CodeIn = None, request: Request = None,
                 session: Session = Depends(get_session),
                 x_api_key: str = Header(default="", alias="X-API-Key"),
                 authorization: str = Header(default="")):
    user = _current_user(request, session, x_api_key, authorization)
    if not user.totp_secret:
        raise HTTPException(status.HTTP_409_CONFLICT, "start enrolment first")
    if payload is None or not mfa.verify(user.totp_secret, payload.code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "code did not match")
    user.totp_enabled_at = models.utcnow()
    user.updated_at = user.totp_enabled_at
    codes = _replace_recovery_codes(session, user)
    _audit_log(session, user.org_id, user.email, "auth.mfa_enabled", "user", user.id, "")
    session.commit()
    return {"data": {"enabled": True, "recovery_codes": codes,
                     "note": "these codes are shown once; each works a single time"}}


@router.post("/mfa/disable")
def mfa_disable(payload: CodeIn = None, request: Request = None,
                session: Session = Depends(get_session),
                x_api_key: str = Header(default="", alias="X-API-Key"),
                authorization: str = Header(default="")):
    user = _current_user(request, session, x_api_key, authorization)
    if not user.totp_enabled_at:
        raise HTTPException(status.HTTP_409_CONFLICT, "multi-factor is not enabled")
    if payload is None or not _verify_second_factor(session, user, payload.code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "code did not match")
    user.totp_secret = None
    user.totp_enabled_at = None
    user.updated_at = models.utcnow()
    for row in session.query(models.MfaRecoveryCode).filter_by(user_id=user.id):
        session.delete(row)
    _audit_log(session, user.org_id, user.email, "auth.mfa_disabled", "user", user.id, "")
    session.commit()
    return {"data": {"enabled": False}}


@router.post("/mfa/recovery-codes")
def mfa_recovery_codes(payload: PasswordIn = None, request: Request = None,
                       session: Session = Depends(get_session),
                       x_api_key: str = Header(default="", alias="X-API-Key"),
                       authorization: str = Header(default="")):
    user = _current_user(request, session, x_api_key, authorization)
    _require_password(user, payload.password if payload else "")
    if not user.totp_enabled_at:
        raise HTTPException(status.HTTP_409_CONFLICT, "multi-factor is not enabled")
    codes = _replace_recovery_codes(session, user)
    _audit_log(session, user.org_id, user.email, "auth.mfa_recovery_rotated",
               "user", user.id, "")
    session.commit()
    return {"data": {"recovery_codes": codes}}


@router.post("/mfa/verify")
def mfa_verify(payload: VerifyIn = None, request: Request = None,
               session: Session = Depends(get_session)):
    """Second step of the login: exchange a challenge for a session."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    row = (session.query(models.MfaChallenge)
           .filter_by(token_hash=auth_local.token_hash(payload.challenge))
           .one_or_none())
    # One message for every failure: no signal about which part was wrong.
    invalid = HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid challenge or code")
    if row is None or row.consumed_at is not None:
        raise invalid
    if auth_local.ensure_aware(row.expires_at) <= models.utcnow():
        raise invalid
    if row.attempts >= MAX_ATTEMPTS:
        row.consumed_at = models.utcnow()
        session.commit()
        raise invalid
    user = session.get(models.User, row.user_id)
    if user is None or user.status != "active":
        raise invalid
    row.attempts += 1
    if not _verify_second_factor(session, user, payload.code):
        session.commit()
        raise invalid
    row.consumed_at = models.utcnow()
    _audit_log(session, user.org_id, user.email, "auth.login_mfa", "user", user.id,
               request.headers.get("user-agent", "")[:120] if request else "")
    session.commit()
    return {"data": _user_data(user), "session": _issue_session(session, user)}


def issue_challenge(session: Session, user: models.User) -> dict:
    """Called by /auth/login when the user has an active second factor."""
    raw = auth_local.new_session_token()
    now = models.utcnow()
    session.add(models.MfaChallenge(
        org_id=user.org_id, user_id=user.id,
        token_hash=auth_local.token_hash(raw), created_at=now,
        expires_at=now + datetime.timedelta(minutes=CHALLENGE_TTL_MINUTES),
        attempts=0))
    session.commit()
    return {"challenge": raw, "expires_in": CHALLENGE_TTL_MINUTES * 60,
            "methods": ["totp", "recovery_code"]}

"""Deployment-wide settings an operator can change without a restart.

Email delivery is the first one. It belongs to the installation, not to an
organization: one SMTP relay serves every invitation and every notification
channel, and the console shows who changed it and when.

The password is write-only. It is sealed with the platform key, never returned,
and a blank field on save means "keep the stored one".
"""
import re

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, mail, models
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1/deployment", tags=["deployment"])

HOST_PATTERN = re.compile(r"^[A-Za-z0-9.\-]+$")


class MailIn(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=25, ge=1, le=65535)
    sender: str = Field(min_length=3, max_length=320)
    user: str | None = Field(default="", max_length=255)
    # Write-only. Empty keeps whatever is stored; `clear_password` removes it.
    password: str | None = Field(default="", max_length=512)
    starttls: bool = False
    clear_password: bool = False
    actor: str = Field(default="console", max_length=320)


@router.get("/mail")
def read_mail(org: models.Organization = Depends(auth.require_admin),
              session: Session = Depends(get_session)):
    return {"data": mail.status(session)}


@router.put("/mail")
def save_mail(payload: MailIn = None,
              org: models.Organization = Depends(auth.require_admin),
              session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    host = payload.host.strip()
    if "://" in host or "/" in host:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "host is a mail server name, not a URL")
    if not HOST_PATTERN.match(host):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "host contains characters a mail server name cannot have")
    sender = payload.sender.strip()
    if "@" not in sender:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "sender must be an email address")
    if payload.clear_password and (payload.password or "").strip():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "send a password or clear it, not both")
    if payload.user and not payload.password and not payload.clear_password \
            and not mail.status(session)["password_set"]:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "a username needs a password")
    result = mail.save(session, {"host": host, "port": payload.port,
                                 "sender": sender,
                                 "user": (payload.user or "").strip(),
                                 "password": payload.password,
                                 "starttls": payload.starttls,
                                 "clear_password": payload.clear_password},
                       payload.actor)
    _audit_log(session, org.id, payload.actor, "deployment.mail_configured",
               "platform_setting", mail.ROW_NAME,
               f"{host}:{payload.port} from {sender}")
    session.commit()
    return {"data": result}


@router.delete("/mail")
def clear_mail(actor: str = "console",
               org: models.Organization = Depends(auth.require_admin),
               session: Session = Depends(get_session)):
    """Drop the console configuration; the environment variables take over again."""
    mail.clear(session)
    _audit_log(session, org.id, actor, "deployment.mail_cleared",
               "platform_setting", mail.ROW_NAME, "falling back to SMTP_* env")
    session.commit()
    return {"data": mail.status(session)}


class MailTestIn(BaseModel):
    to: str = Field(min_length=3, max_length=320)
    actor: str = Field(default="console", max_length=320)


@router.post("/mail/test")
def test_mail(payload: MailTestIn = None,
              org: models.Organization = Depends(auth.require_admin),
              session: Session = Depends(get_session)):
    """Send one real message. A configuration is only real when a server takes it."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    to = payload.to.strip()
    if "@" not in to:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "that does not look like an email address")
    current = mail.resolve(session)
    delivered, reason = mail.send(
        to, "[Barad-dûr] mail delivery test",
        "This is a test message from Barad-dûr.\n\n"
        f"Server: {current['host']}:{current['port']}\n"
        f"Sender: {current['sender']}\n"
        f"Configuration source: {current['source']}\n\n"
        "If you are reading this, invitations can be emailed.\n",
        session=session)
    _audit_log(session, org.id, payload.actor,
               "deployment.mail_test" if delivered else "deployment.mail_test_failed",
               "platform_setting", mail.ROW_NAME,
               (f"to {to}" if delivered else reason)[:300])
    session.commit()
    if not delivered:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, reason)
    return {"data": {"delivered": True, "to": to, "source": current["source"]}}

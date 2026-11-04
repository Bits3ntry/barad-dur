"""Outbound email for invitations and notification channels.

Delivery is resolved in this order:

1. A `platform_settings` row named `smtp` — what an operator saved in the
   console. An explicit choice beats ambient configuration.
2. The deployment's `SMTP_*` environment variables.
3. Nothing, in which case `send` answers `smtp_not_configured` and the caller
   must show the invite link instead of claiming a message left the building.

The password never leaves the server: it is sealed with the platform key before
it is stored, and only `password_set` is ever reported back.
"""
import json
import os
import smtplib
from email.message import EmailMessage

from sqlalchemy.orm import Session

from backend.app import auth_local, models, secrets as secret_store

ROW_NAME = "smtp"

DEFAULTS = {"host": "", "port": 25, "sender": "barad-dur@localhost",
            "user": "", "password": "", "starttls": False}


def environment_settings() -> dict:
    return {"host": os.environ.get("SMTP_HOST") or "",
            "port": int(os.environ.get("SMTP_PORT") or 25),
            "sender": os.environ.get("SMTP_FROM") or "barad-dur@localhost",
            "user": os.environ.get("SMTP_USER") or "",
            "password": os.environ.get("SMTP_PASSWORD") or "",
            "starttls": (os.environ.get("SMTP_STARTTLS") or "").lower() in
                        {"1", "true", "yes"}}


def stored(session: Session | None) -> dict | None:
    """The console-saved configuration, decrypted, or None when absent."""
    if session is None:
        return None
    row = session.get(models.PlatformSetting, ROW_NAME)
    if row is None:
        return None
    try:
        payload = json.loads(row.value or "{}")
    except json.JSONDecodeError:
        payload = {}
    password = ""
    if row.secret_cipher:
        try:
            password = secret_store.open_sealed(session, row.secret_cipher)
        except ValueError:
            # A rotated platform key leaves an unreadable password. Report the
            # configuration rather than silently sending unauthenticated.
            password = ""
    return {"host": payload.get("host") or "",
            "port": int(payload.get("port") or 25),
            "sender": payload.get("sender") or DEFAULTS["sender"],
            "user": payload.get("user") or "",
            "password": password,
            "starttls": bool(payload.get("starttls")),
            "configured_password": bool(row.secret_cipher),
            "updated_at": row.updated_at,
            "updated_by": row.updated_by}


def resolve(session: Session | None = None) -> dict:
    saved = stored(session)
    if saved is not None:
        return {**saved, "source": "database"}
    return {**environment_settings(),
            "source": "environment" if os.environ.get("SMTP_HOST") else "none"}


def configured(session: Session | None = None) -> bool:
    return bool(resolve(session)["host"])


def status(session: Session | None = None) -> dict:
    """Public shape: everything an operator needs, minus the password itself."""
    current = resolve(session)
    updated = auth_local.ensure_aware(current.get("updated_at"))
    return {"configured": bool(current["host"]),
            "host": current["host"], "port": current["port"],
            "sender": current["sender"], "user": current["user"],
            "starttls": current["starttls"],
            "source": current["source"],
            "password_set": bool(current.get("password")),
            "updated_at": updated.isoformat() if updated else None,
            "updated_by": current.get("updated_by")}


def save(session: Session, payload: dict, actor: str) -> dict:
    """Persist the console configuration. A blank password keeps the old one."""
    row = session.get(models.PlatformSetting, ROW_NAME)
    if row is None:
        row = models.PlatformSetting(name=ROW_NAME, value="{}")
        session.add(row)
    password = (payload.get("password") or "").strip()
    if password:
        row.secret_cipher = secret_store.seal(session, password)
    elif payload.get("clear_password"):
        row.secret_cipher = None
    row.value = json.dumps({"host": payload["host"],
                            "port": int(payload["port"]),
                            "sender": payload["sender"],
                            "user": payload.get("user") or "",
                            "starttls": bool(payload.get("starttls"))})
    row.updated_at = models.utcnow()
    row.updated_by = actor
    session.commit()
    return status(session)


def clear(session: Session) -> None:
    row = session.get(models.PlatformSetting, ROW_NAME)
    if row is not None:
        session.delete(row)
        session.commit()


def send(to: str, subject: str, body: str, session: Session | None = None,
         timeout: float = 8.0) -> tuple[bool, str]:
    """Return (delivered, reason). `reason` is empty on success."""
    current = resolve(session)
    if not current["host"]:
        return False, ("smtp_not_configured: save a mail server in Settings or "
                       "set SMTP_HOST")
    message = EmailMessage()
    message["From"] = current["sender"]
    message["To"] = to
    message["Subject"] = subject
    message.set_content(body)
    try:
        with smtplib.SMTP(current["host"], current["port"], timeout=timeout) as smtp:
            if current["starttls"]:
                smtp.starttls()
            if current["user"]:
                smtp.login(current["user"], current["password"])
            smtp.send_message(message)
        return True, ""
    except (smtplib.SMTPException, OSError) as exc:
        return False, f"smtp_error: {type(exc).__name__}: {exc}"[:400]

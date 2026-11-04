"""Symmetric protection for credentials that must be replayed later.

Integration tokens are the one secret the platform has to *use* after storing
it, so a hash is not enough. They are sealed with Fernet (AES-128-CBC + HMAC)
before they reach the database and are never returned by the API.

Key material, in order of preference:

1. `PLATFORM_SECRET_KEY` from the environment. Production sets it, so the key
   never shares storage with the data it protects.
2. A generated key in `platform_secrets`. This is the fresh-installation path:
   it still protects against a database dump pasted into a ticket, and the
   onboarding status says which source is in use so the operator can move to
   option 1 without guessing.
"""
import base64
import hashlib
import os
import secrets

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.orm import Session

from backend.app import models

ENV_KEY = "PLATFORM_SECRET_KEY"
ROW_NAME = "integration_key"


def key_source(session: Session) -> str:
    return "environment" if os.environ.get(ENV_KEY) else \
        ("database" if session.get(models.PlatformSecret, ROW_NAME) else "generated")


def _fernet(session: Session) -> Fernet:
    raw = os.environ.get(ENV_KEY) or ""
    if not raw:
        row = session.get(models.PlatformSecret, ROW_NAME)
        if row is None:
            row = models.PlatformSecret(name=ROW_NAME, value=secrets.token_hex(32),
                                        created_at=models.utcnow())
            session.add(row)
            session.flush()
        raw = row.value
    digest = hashlib.sha256(raw.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def seal(session: Session, plaintext: str) -> str:
    return _fernet(session).encrypt(plaintext.encode("utf-8")).decode("ascii")


def open_sealed(session: Session, cipher: str) -> str:
    """Raise ValueError when the cipher cannot be opened with the current key."""
    try:
        return _fernet(session).decrypt(cipher.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError) as exc:
        raise ValueError("stored credential cannot be decrypted with this key") from exc

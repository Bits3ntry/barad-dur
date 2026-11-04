"""Ticket signing: Ed25519, asymmetric on purpose.

The private key never leaves this process, and the daemon is configured with the
public key only. A shared HMAC secret would let a compromised Shauron mint a
ticket for a target it was never given — which is exactly the boundary this
product exists to keep.

`canonical_bytes` is duplicated verbatim in `shauron/contract.py`. Both sides are
pinned by the same fixture: one byte of disagreement fails every signature, which
is the right failure but an expensive one to discover late.
"""
from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.orm import Session

from backend.app import models, secrets

ENV_KEY = "SCAN_SIGNING_KEY"
ROW_NAME = "scan_signing_key"
KEY_ID = "barad-scan-v1"
SIGNATURE_FIELD = "signature"


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def canonical_bytes(document: dict) -> bytes:
    """The exact bytes the signature covers: everything except the signature."""
    payload = {k: v for k, v in document.items() if k != SIGNATURE_FIELD}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _private(session: Session) -> Ed25519PrivateKey:
    """Environment first, sealed database row second, generated once third."""
    raw = os.environ.get(ENV_KEY, "").strip()
    if raw:
        return Ed25519PrivateKey.from_private_bytes(_b64d(raw))
    row = session.get(models.PlatformSecret, ROW_NAME)
    if row is None:
        seed = Ed25519PrivateKey.generate().private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption())
        row = models.PlatformSecret(
            name=ROW_NAME, value=secrets.seal(session, _b64e(seed)))
        session.add(row)
        session.flush()
    return Ed25519PrivateKey.from_private_bytes(_b64d(secrets.open_sealed(session, row.value)))


def key_source(session: Session) -> str:
    if os.environ.get(ENV_KEY):
        return "environment"
    if session.get(models.PlatformSecret, ROW_NAME) is not None:
        return "database"
    return "generated"


def public_key_b64(session: Session) -> str:
    raw = _private(session).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    return _b64e(raw)


def sign_ticket(session: Session, ticket: dict) -> dict:
    """Sign in place and return the document; `key_id` rides beside the signature."""
    document = {k: v for k, v in ticket.items() if k != SIGNATURE_FIELD}
    document["key_id"] = KEY_ID
    signature = _private(session).sign(canonical_bytes(document))
    document[SIGNATURE_FIELD] = "ed25519:" + _b64e(signature)
    return document

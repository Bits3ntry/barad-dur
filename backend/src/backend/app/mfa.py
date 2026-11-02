"""TOTP second factor, implemented with the standard library.

RFC 6238 over RFC 4226: HMAC-SHA1, 30-second steps, 6 digits, base32 secret.
The same secret never leaves the server except once, in the enrolment response,
where the client renders it as an otpauth:// URI. Recovery codes are random,
shown once and stored as SHA-256 hashes.
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse

STEP_SECONDS = 30
DIGITS = 6
SECRET_BYTES = 20
RECOVERY_CODE_COUNT = 8
# One step of tolerance each way: a phone clock a few seconds off still works,
# a stolen code is useless after ~90 s.
WINDOW = 1


def generate_secret() -> str:
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode().rstrip("=")


def _decode(secret: str) -> bytes:
    padding = "=" * (-len(secret) % 8)
    return base64.b32decode(secret.upper() + padding)


def code_at(secret: str, counter: int) -> str:
    digest = hmac.new(_decode(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** DIGITS)).zfill(DIGITS)


def verify(secret: str, code: str, now: float | None = None) -> bool:
    """Constant-time check of a 6-digit code within the tolerance window."""
    candidate = "".join(ch for ch in str(code or "") if ch.isdigit())
    if len(candidate) != DIGITS or not secret:
        return False
    counter = int((now if now is not None else time.time()) // STEP_SECONDS)
    ok = False
    for offset in range(-WINDOW, WINDOW + 1):
        if hmac.compare_digest(code_at(secret, counter + offset), candidate):
            ok = True
    return ok


def provisioning_uri(secret: str, account: str, issuer: str = "Barad-dûr") -> str:
    label = f"{issuer}:{account}"
    params = urllib.parse.urlencode({
        "secret": secret, "issuer": issuer, "algorithm": "SHA1",
        "digits": DIGITS, "period": STEP_SECONDS,
    })
    return f"otpauth://totp/{urllib.parse.quote(label)}?{params}"


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    """Human-transcribable codes: 10 base32 characters in two groups."""
    codes = []
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    for _ in range(count):
        raw = "".join(secrets.choice(alphabet) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def normalise_recovery_code(code: str) -> str:
    return "".join(ch for ch in str(code or "").upper() if ch.isalnum())

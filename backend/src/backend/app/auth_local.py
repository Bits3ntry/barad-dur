"""Local credentials, opaque sessions and the OIDC client.

Password hashing uses stdlib scrypt (no third-party crypto needed). Session
tokens are random and stored only as SHA-256 hashes, so a database leak does
not hand out live sessions.

OIDC needs RS256 verification, which requires the optional `cryptography`
dependency (`pip install barad-platform[oidc]`). When it is missing the
endpoints answer 503 with an explicit reason instead of accepting unverified
tokens.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.parse
import urllib.request

SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
TOKEN_TTL_HOURS = int(os.environ.get("SESSION_TTL_HOURS") or 12)
<<<<<<< Updated upstream
REFRESH_TTL_DAYS = int(os.environ.get("REFRESH_TTL_DAYS") or 7)
=======
>>>>>>> Stashed changes


class AuthError(RuntimeError):
    pass


class OidcError(AuthError):
    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.status_code = status_code


# ── passwords ────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    if not password or len(password) < 8:
        raise AuthError("password must be at least 8 characters")
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N,
                             r=SCRYPT_R, p=SCRYPT_P, dklen=32)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${derived.hex()}"


def verify_password(stored: str, password: str) -> bool:
    try:
        scheme, n, r, p, salt_hex, hash_hex = (stored or "").split("$")
        if scheme != "scrypt":
            return False
        derived = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex),
                                 n=int(n), r=int(r), p=int(p), dklen=len(hash_hex) // 2)
        return hmac.compare_digest(derived.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


# ── sessions ─────────────────────────────────────────────────────────────────

def new_session_token() -> str:
    return secrets.token_urlsafe(32)


<<<<<<< Updated upstream
def new_refresh_token() -> str:
    return secrets.token_urlsafe(40)


=======
>>>>>>> Stashed changes
def token_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def ensure_aware(value):
    """SQLite hands back naive datetimes; compare them safely."""
    import datetime

    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=datetime.timezone.utc)
    return value


def session_expiry(hours: int | None = None):
    import datetime

<<<<<<< Updated upstream
    return datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        hours=hours or TOKEN_TTL_HOURS)


def refresh_expiry(days: int | None = None):
    """Absolute expiry for the long-lived refresh token (not the access token)."""
    import datetime

    return datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        days=days or REFRESH_TTL_DAYS)
=======
    return datetime.datetime.now(datetime.timezone.utc) + \
        datetime.timedelta(hours=hours or TOKEN_TTL_HOURS)
>>>>>>> Stashed changes


# ── OIDC ─────────────────────────────────────────────────────────────────────

def oidc_settings() -> dict:
    return {"issuer": (os.environ.get("OIDC_ISSUER") or "").rstrip("/"),
            "client_id": os.environ.get("OIDC_CLIENT_ID") or "",
            "client_secret": os.environ.get("OIDC_CLIENT_SECRET") or "",
            "redirect_uri": os.environ.get("OIDC_REDIRECT_URI") or ""}


def oidc_configured() -> bool:
    settings = oidc_settings()
    return bool(settings["issuer"] and settings["client_id"]
                and settings["client_secret"] and settings["redirect_uri"])


def _crypto_available() -> bool:
    try:
        import cryptography  # noqa: F401
        return True
    except Exception:
        return False


def _get_json(url: str, timeout: float = 8.0) -> dict:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode() or "{}")


def discover() -> dict:
    settings = oidc_settings()
    if not oidc_configured():
        raise OidcError("oidc_not_configured", 503)
    metadata = _get_json(f"{settings['issuer']}/.well-known/openid-configuration")
    for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not metadata.get(field):
            raise OidcError(f"oidc_metadata_missing_{field}", 502)
    return metadata


def authorization_url(state: str, nonce: str) -> str:
    settings = oidc_settings()
    metadata = discover()
    params = urllib.parse.urlencode({
        "response_type": "code", "client_id": settings["client_id"],
        "redirect_uri": settings["redirect_uri"], "scope": "openid email profile",
        "state": state, "nonce": nonce})
    return f"{metadata['authorization_endpoint']}?{params}"


def _post_form(url: str, data: dict, timeout: float = 10.0) -> dict:
    body = urllib.parse.urlencode(data).encode()
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    request.add_header("Accept", "application/json")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode() or "{}")


def exchange_code(code: str) -> dict:
    settings = oidc_settings()
    metadata = discover()
    return _post_form(metadata["token_endpoint"], {
        "grant_type": "authorization_code", "code": code,
        "client_id": settings["client_id"],
        "client_secret": settings["client_secret"],
        "redirect_uri": settings["redirect_uri"]})


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def verify_id_token(id_token: str, nonce: str | None = None) -> dict:
    """Verify signature (RS256) and standard claims; raise OidcError otherwise."""
    if not _crypto_available():
        raise OidcError("oidc_requires_cryptography_extra", 503)
    settings = oidc_settings()
    try:
        header_b64, payload_b64, signature_b64 = id_token.split(".")
        header = json.loads(_b64url_decode(header_b64))
        claims = json.loads(_b64url_decode(payload_b64))
        signature = _b64url_decode(signature_b64)
    except (ValueError, json.JSONDecodeError):
        raise OidcError("oidc_token_malformed")
    if header.get("alg") != "RS256":
        raise OidcError(f"oidc_algorithm_rejected_{header.get('alg')}")

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    metadata = discover()
    keys = _get_json(metadata["jwks_uri"]).get("keys") or []
    key = next((k for k in keys if k.get("kid") == header.get("kid")), None)
    if key is None:
        raise OidcError("oidc_signing_key_not_found", 502)
    if key.get("kty") != "RSA":
        raise OidcError("oidc_key_type_unsupported")
    n = int.from_bytes(_b64url_decode(key["n"]), "big")
    e = int.from_bytes(_b64url_decode(key["e"]), "big")
    public_key = rsa.RSAPublicNumbers(e, n).public_key()
    try:
        public_key.verify(signature, f"{header_b64}.{payload_b64}".encode(),
                          padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        raise OidcError("oidc_signature_invalid")

    now = int(time.time())
    if int(claims.get("exp", 0)) < now:
        raise OidcError("oidc_token_expired")
    if claims.get("iss", "").rstrip("/") != settings["issuer"]:
        raise OidcError("oidc_issuer_mismatch")
    audience = claims.get("aud")
    audiences = audience if isinstance(audience, list) else [audience]
    if settings["client_id"] not in audiences:
        raise OidcError("oidc_audience_mismatch")
    if nonce is not None and claims.get("nonce") != nonce:
        raise OidcError("oidc_nonce_mismatch")
    return claims

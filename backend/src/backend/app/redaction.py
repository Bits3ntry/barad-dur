"""Shared redaction helpers (findings, regression evidence, code viewer).

Rule: secret-bearing headers are replaced wholesale; credential-looking
text (``token=``, ``api_key=``, ``password=`` ...) is scrubbed in place.
Nothing here decides *whether* to store data — callers own the boundary.
"""
import re

SECRET_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key",
                  "proxy-authorization", "x-auth-token"}

SECRET_PATTERN = re.compile(
    r"(?i)\b(authorization|api[-_]?key|access[-_]?token|refresh[-_]?token|"
    r"token|secret|password|passwd|cookie|session[-_]?id|bearer)\b"
    r"\s*[:=]\s*['\"]?[^\s,;'\"]+['\"]?")


def redact_headers(headers: dict) -> dict:
    return {key: ("[REDACTED]" if str(key).lower() in SECRET_HEADERS else value)
            for key, value in (headers or {}).items()}


def redact_text(text: str) -> str:
    return SECRET_PATTERN.sub(lambda match: f"{match.group(1)}=[REDACTED]",
                              text or "")

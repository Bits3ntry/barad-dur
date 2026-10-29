"""Small, opinionated HTTP client for the publication adapters.

Rules that matter for a security runner:

* no environment proxy and no redirects, so a token can never be replayed to a
  host the repository did not name (`build_opener(ProxyHandler({}), NoRedirect())`);
* bounded retries with exponential backoff, and every attempt is recorded so the
  manifest can prove what happened;
* a retry of a non-idempotent write only happens when the caller supplies an
  idempotency key, otherwise a 5xx is reported instead of risking duplicates.
"""
import json
import random
import socket
import time
from dataclasses import dataclass, field
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
IDEMPOTENCY_HEADER = "Idempotency-Key"
# Safe to replay by HTTP semantics even without a caller-supplied key.
_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "PUT", "DELETE", "OPTIONS"})


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


@dataclass
class Response:
    status: int
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    attempts: list = field(default_factory=list)
    url: str = ""

    def json(self):
        if not self.body:
            return None
        return json.loads(self.body.decode("utf-8"))

    @property
    def ok(self):
        return 200 <= self.status < 300


class HttpStatusError(Exception):
    def __init__(self, status, body, attempts, url):
        self.status = status
        self.body = body
        self.attempts = attempts
        super().__init__(f"HTTP {status} from {_safe_url(url)}")

    def snippet(self, limit=300):
        try:
            text = self.body.decode("utf-8", "replace").strip()
        except Exception:  # pragma: no cover - defensive
            return ""
        return " ".join(text.split())[:limit]


class HttpTransportError(Exception):
    def __init__(self, reason, attempts, url):
        self.reason = reason
        self.attempts = attempts
        super().__init__(f"transport error ({reason}) for {_safe_url(url)}")


def _safe_url(url):
    """Never echo credentials that a caller may have embedded in a URL."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{host}{port}{parsed.path}"


def validate_endpoint(url, *, name="endpoint"):
    """Reject anything that is not a plain http(s) base URL without credentials."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError(f"{name} is not configured")
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"{name} must be an http(s) URL")
    if not parsed.hostname:
        raise ValueError(f"{name} has no host")
    if parsed.username or parsed.password:
        raise ValueError(f"{name} must not embed credentials; use the token environment variable")
    if parsed.query or parsed.fragment:
        raise ValueError(f"{name} must not carry a query string or fragment")
    return url.strip().rstrip("/")


class HttpClient:
    def __init__(self, *, timeout=30.0, max_attempts=3, backoff=0.5, max_backoff=8.0,
                 logger=None, log_step="publish", sleeper=time.sleep, opener=None):
        self.timeout = float(timeout)
        self.max_attempts = max(1, int(max_attempts))
        self.backoff = float(backoff)
        self.max_backoff = float(max_backoff)
        self.logger = logger
        self.log_step = log_step
        self.sleeper = sleeper
        self._opener = opener or build_opener(ProxyHandler({}), _NoRedirect())

    def request(self, method, url, *, headers=None, json_body=None, body=None,
                content_type=None, idempotent=False):
        request_headers = dict(headers or {})
        payload = body
        if json_body is not None:
            payload = json.dumps(json_body).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        elif content_type:
            request_headers.setdefault("Content-Type", content_type)

        retryable_write = (
            idempotent
            or method.upper() in _IDEMPOTENT_METHODS
            or IDEMPOTENCY_HEADER in request_headers
        )
        attempts = []
        for attempt in range(1, self.max_attempts + 1):
            started = time.monotonic()
            try:
                request = Request(url, data=payload, method=method, headers=request_headers)
                with self._opener.open(request, timeout=self.timeout) as response:
                    data = response.read()
                    status = response.status
                    response_headers = dict(response.headers.items())
                attempts.append({"attempt": attempt, "status": status,
                                 "duration_ms": _ms(started)})
                self._log("http_request", method, url, attempt, status)
                return Response(status=status, headers=response_headers, body=data,
                                attempts=attempts, url=url)
            except HTTPError as error:
                body_bytes = b""
                try:
                    body_bytes = error.read()
                except Exception:  # pragma: no cover - defensive
                    body_bytes = b""
                status = error.code
                attempts.append({"attempt": attempt, "status": status,
                                 "duration_ms": _ms(started)})
                self._log("http_error", method, url, attempt, status)
                if status in RETRY_STATUS and retryable_write and attempt < self.max_attempts:
                    self._sleep(attempt, error.headers.get("Retry-After") if error.headers else None)
                    continue
                raise HttpStatusError(status, body_bytes, attempts, url) from None
            except (URLError, socket.timeout, TimeoutError, ConnectionError) as error:
                reason = getattr(error, "reason", error)
                attempts.append({"attempt": attempt, "status": None,
                                 "error": type(reason).__name__,
                                 "duration_ms": _ms(started)})
                self._log("http_transport_error", method, url, attempt, None,
                          error=type(reason).__name__)
                if attempt < self.max_attempts:
                    self._sleep(attempt, None)
                    continue
                raise HttpTransportError(type(reason).__name__, attempts, url) from None
        raise HttpTransportError("retries_exhausted", attempts, url)  # pragma: no cover

    def _sleep(self, attempt, retry_after):
        try:
            delay = float(retry_after) if retry_after else self.backoff * (2 ** (attempt - 1))
        except (TypeError, ValueError):
            delay = self.backoff * (2 ** (attempt - 1))
        delay = min(delay, self.max_backoff)
        delay += random.uniform(0, min(delay * 0.1, 0.25))
        self.sleeper(max(delay, 0.0))

    def _log(self, event, method, url, attempt, status, error=None):
        if self.logger is None:
            return
        details = {"method": method, "url": _safe_url(url), "attempt": attempt,
                   "max_attempts": self.max_attempts}
        if status is not None:
            details["status"] = status
        if error:
            details["error"] = error
        if status is not None and 200 <= status < 300:
            self.logger.debug(self.log_step, event, details)
        else:
            self.logger.warning(self.log_step, event, details)


def _ms(started):
    return int((time.monotonic() - started) * 1000)


def multipart(fields, files=None, boundary="----barad-dur-boundary"):
    """Build a multipart/form-data body without a third-party dependency.

    `files` maps field name -> (filename, bytes, content_type).
    """
    chunks = []
    for name, value in fields.items():
        if value is None:
            continue
        chunks.append(f"--{boundary}\r\n".encode("utf-8"))
        chunks.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("utf-8"))
        chunks.append(str(value).encode("utf-8"))
        chunks.append(b"\r\n")
    for name, (filename, content, content_type) in (files or {}).items():
        chunks.append(f"--{boundary}\r\n".encode("utf-8"))
        chunks.append(
            f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode("utf-8")
        )
        chunks.append(f"Content-Type: {content_type}\r\n\r\n".encode("utf-8"))
        chunks.append(content)
        chunks.append(b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode("utf-8"))
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"

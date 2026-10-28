"""Structured JSON Lines logging plus a readable terminal line for humans.

Two sinks, one event: every record goes to `execution.log` (JSONL, the machine
contract) and to stderr (readable, never required for parsing). Secrets are
redacted in both sinks before serialization, so a credential can never reach a
persisted artifact through a log line.
"""
import json
import os
import sys
import threading
from datetime import datetime, timezone

LEVELS = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40}

REDACTED = "[REDACTED]"

# Header-shaped secrets that may appear in a stringified request or error.
_SENSITIVE_HEADERS = (
    "x-api-key",
    "authorization",
    "proxy-authorization",
    "trivy-token",
    "cookie",
)


class Redactor:
    """Replace known secret values and sensitive header values with a marker."""

    def __init__(self, secrets=()):
        unique = {str(value) for value in secrets if value and len(str(value)) >= 6}
        self._secrets = sorted(unique, key=len, reverse=True)

    @classmethod
    def from_environment(cls, names):
        """Collect the values of the named environment variables, never their names."""
        return cls(os.environ.get(name, "") for name in names or ())

    def extend(self, other):
        return Redactor(self._secrets + list(getattr(other, "_secrets", ())))

    def text(self, value):
        if not isinstance(value, str) or not value:
            return value
        out = value
        for secret in self._secrets:
            if secret in out:
                out = out.replace(secret, REDACTED)
        return out

    def data(self, value):
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            return {self.text(str(key)): self.data(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.data(item) for item in value]
        return value

    def headers(self, headers):
        """Return a loggable copy of an HTTP header mapping."""
        safe = {}
        for key, value in (headers or {}).items():
            if str(key).lower() in _SENSITIVE_HEADERS:
                safe[str(key)] = REDACTED
            else:
                safe[str(key)] = self.text(str(value))
        return safe


def utc_now():
    return datetime.now(timezone.utc)


def utc_timestamp(moment=None):
    return (moment or utc_now()).strftime("%Y-%m-%dT%H:%M:%SZ")


class Logger:
    """Append-only structured logger bound to one run id."""

    def __init__(self, run_id, *, path=None, stream=None, level="INFO", redactor=None):
        self.run_id = run_id
        self.path = path
        self.stream = stream if stream is not None else sys.stderr
        self.level = level if level in LEVELS else "INFO"
        self.redactor = redactor or Redactor()
        self._lock = threading.Lock()
        self.records = []

    def bind(self, **kwargs):
        """Return a logger sharing sinks but with extra default detail fields."""
        bound = _BoundLogger(self, kwargs)
        return bound

    def _emit(self, level, step, event, details):
        if LEVELS[level] < LEVELS[self.level]:
            return
        record = {
            "timestamp": utc_timestamp(),
            "run_id": self.run_id,
            "level": level,
            "step": step,
            "event": event,
        }
        if details:
            record["details"] = details
        record = self.redactor.data(record)
        line = json.dumps(record, ensure_ascii=False, sort_keys=True)
        human_details = ""
        if record.get("details"):
            human_details = " " + json.dumps(record["details"], ensure_ascii=False, sort_keys=True)
        human = f"{record['timestamp']} {level:<7} [{step}] {event}{human_details}"
        with self._lock:
            self.records.append(record)
            if self.path is not None:
                try:
                    self.path.parent.mkdir(parents=True, exist_ok=True)
                    with self.path.open("a", encoding="utf-8") as handle:
                        handle.write(line + "\n")
                except OSError:
                    # Logging must never be the reason a security run dies.
                    pass
            if self.stream is not None:
                try:
                    print(human, file=self.stream, flush=True)
                except (OSError, ValueError):
                    pass

    def debug(self, step, event, details=None):
        self._emit("DEBUG", step, event, details)

    def info(self, step, event, details=None):
        self._emit("INFO", step, event, details)

    def warning(self, step, event, details=None):
        self._emit("WARNING", step, event, details)

    def error(self, step, event, details=None):
        self._emit("ERROR", step, event, details)


class _BoundLogger:
    """Logger wrapper that merges constant detail fields into every record."""

    def __init__(self, logger, defaults):
        self._logger = logger
        self._defaults = defaults

    def _emit(self, level, step, event, details):
        merged = dict(self._defaults)
        merged.update(details or {})
        self._logger._emit(level, step, event, merged)

    def debug(self, step, event, details=None):
        self._emit("DEBUG", step, event, details)

    def info(self, step, event, details=None):
        self._emit("INFO", step, event, details)

    def warning(self, step, event, details=None):
        self._emit("WARNING", step, event, details)

    def error(self, step, event, details=None):
        self._emit("ERROR", step, event, details)


def null_logger(run_id="-"):  # pragma: no cover - convenience for library tests
    return Logger(run_id, stream=None)

"""The publication contract shared by every integration.

An adapter receives a `PublishContext` (already-computed evidence, never a
scanner), returns a `PublicationResult`, and is allowed to fail: optional
integrations record PENDING or FAILED evidence and the analysis result survives.
It must never retry a completed publication, and it must never print, log or
persist a token.
"""
from dataclasses import dataclass, field
from pathlib import Path

from ..errors import PublishError
from ..http import HttpClient, validate_endpoint

PUBLISHED = "PUBLISHED"
DUPLICATE = "DUPLICATE"
SKIPPED = "SKIPPED"
FAILED = "FAILED"
PENDING = "PENDING"
DEFERRED = PENDING


@dataclass
class PublishContext:
    """Everything a publisher needs, and nothing it could use to rescan."""

    run_id: str
    event: str
    service: str
    project: str
    version: str = None
    git: dict = field(default_factory=dict)
    run_dir: Path = None
    artifacts: dict = field(default_factory=dict)   # logical name -> absolute Path
    manifest: dict = field(default_factory=dict)
    sbom_path: Path = None
    report_path: Path = None          # sanitised JSON report for outbound use
    raw_report_path: Path = None
    publish_target: str = None        # "release" | "development" | "evidence"
    required: bool = False
    idempotency_key: str = None
    retry_of: str = None

    def artifact(self, name):
        path = self.artifacts.get(name)
        return Path(path) if path else None


@dataclass
class PublicationResult:
    service: str
    status: str
    reason: str = None
    message: str = None
    external_ids: dict = field(default_factory=dict)
    attempts: list = field(default_factory=list)
    artifact: str = None
    detail: dict = field(default_factory=dict)
    required: bool = False

    @property
    def ok(self):
        return self.status in (PUBLISHED, DUPLICATE, SKIPPED)

    def public(self):
        payload = {
            "status": self.status,
            "required": self.required,
            "reason": self.reason,
            "external_ids": dict(self.external_ids),
            "attempts": list(self.attempts),
            "detail": dict(self.detail),
        }
        if self.message:
            payload["message"] = self.message
        if self.artifact:
            payload["artifact"] = self.artifact
        return payload


class Publisher:
    service = "generic"
    log_step = "publish"

    def __init__(self, config, logger):
        self.config = config
        self.logger = logger

    # -- configuration -----------------------------------------------------
    def settings(self):
        return self.config.get(f"integrations.{self.service}", {}) or {}

    def enabled(self):
        return bool(self.settings().get("enabled"))

    def required(self):
        return bool(self.settings().get("required"))

    def endpoint(self):
        """Resolve endpoint and token from the environment; never from the file."""
        endpoint_name, endpoint_value = self.config.env_value(f"integrations.{self.service}.endpoint_env")
        token_name, token_value = self.config.env_value(f"integrations.{self.service}.token_env")
        if not endpoint_value:
            raise PublishError(
                f"{endpoint_name or 'endpoint'} is not set; cannot reach {self.service}",
                service=self.service,
            )
        try:
            url = validate_endpoint(endpoint_value, name=endpoint_name or "endpoint")
        except ValueError as error:
            raise PublishError(str(error), service=self.service) from None
        return url, token_value, token_name

    def client(self):
        settings = self.settings()
        return HttpClient(
            timeout=float(settings.get("timeout_seconds", 30)),
            max_attempts=int(settings.get("max_attempts", 3)),
            logger=self.logger,
            log_step=self.log_step,
        )

    def fail(self, reason, error=None, attempts=None, detail=None):
        message = str(error) if error else reason
        self.logger.warning(self.log_step, "publication_failed",
                            {"service": self.service, "reason": reason, "message": message})
        return PublicationResult(
            service=self.service,
            status=FAILED,
            reason=reason,
            message=message,
            attempts=attempts or [],
            required=self.required(),
            detail=detail or {},
        )

    def skip(self, reason):
        self.logger.info(self.log_step, "publication_skipped", {"service": self.service, "reason": reason})
        return PublicationResult(service=self.service, status=SKIPPED, reason=reason, required=self.required())

    def publish(self, context):  # pragma: no cover - interface
        raise NotImplementedError

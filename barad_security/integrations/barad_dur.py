"""BARAD-DÛR publication adapter (proposed three-call evidence contract).

The endpoints implemented here are a *proposal* (S8): create the security run,
attach every artifact, then mark the run complete. Nothing is assumed about the
remote implementation beyond those three writes, and the analysis result is
never at risk: an unreachable or rejecting BARAD-DÛR only changes the returned
`PublicationResult`.

Idempotency is explicit. The run creation carries `Idempotency-Key: <run_id>`
and every artifact upload carries `<run_id>:<name>`, so a deferred run can be
retried by `barad-security sync` without creating a duplicate. An artifact whose
recorded SHA-256 in `context.known_external_ids["artifacts"]` already matches
the local file is not uploaded again.
"""
from pathlib import Path

from ..errors import PublishError
from ..evidence import sha256_file
from ..http import IDEMPOTENCY_HEADER, HttpStatusError, HttpTransportError, multipart
from .base import PENDING, PUBLISHED, PublicationResult, Publisher

REDACTED = "[REDACTED]"
SNIPPET_LIMIT = 200

# Upload order and source. "artifacts" means `context.artifact(name)`, the other
# two are the sanitised report and the SBOM, which the context exposes directly.
ARTIFACTS = (
    ("manifest.json", "artifacts"),
    ("decisions.json", "artifacts"),
    ("trivy-report.json", "report_path"),
    ("sbom.cdx.json", "sbom_path"),
    ("execution.log", "artifacts"),
    ("checksums.sha256", "artifacts"),
)


def _redact(text, secrets):
    """Strip known credential values from anything that may be persisted."""
    if not text:
        return text
    for secret in sorted({value for value in secrets if value}, key=len, reverse=True):
        text = text.replace(secret, REDACTED)
    return text


def _content_type(name):
    return "text/plain" if name.endswith(".log") else "application/json"


def _timestamps(context):
    manifest = context.manifest or {}
    stamps = manifest.get("timestamps")
    if isinstance(stamps, dict) and stamps:
        return dict(stamps)
    found = {key: manifest[key] for key in ("started_at", "finished_at") if manifest.get(key)}
    return found


def _mapping(value):
    return dict(value) if isinstance(value, dict) else {}


class BaradDurPublisher(Publisher):
    service = "barad_dur"
    log_step = "publish"

    # -- entry point -------------------------------------------------------
    def publish(self, context):
        endpoint, token, problem = self._connection()
        if problem is not None:
            return problem

        client = self.client()
        attempts = []
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

        try:
            created = client.request(
                "POST",
                f"{endpoint}/api/v1/security-runs",
                headers=dict(headers, **{IDEMPOTENCY_HEADER: context.run_id}),
                json_body=self._run_payload(context),
                idempotent=True,
            )
        except (HttpStatusError, HttpTransportError) as error:
            return self._failure(error, attempts, token)
        attempts.extend(created.attempts)

        run_id = self._run_id(created)
        if not run_id:
            return self._deferred(
                "server_error",
                "BARAD-DUR returned no security run identifier",
                attempts,
            )

        known = self._known_artifacts(context)
        uploaded = 0
        skipped = 0
        names = []
        checksums = {}

        for name, source in ARTIFACTS:
            path = self._artifact_path(context, name, source)
            if path is None or not path.is_file():
                continue
            digest = sha256_file(path)
            checksums[name] = digest
            names.append(name)
            if known.get(name) == digest:
                skipped += 1
                self.logger.info(self.log_step, "artifact_skipped", {
                    "service": self.service,
                    "name": name,
                    "sha256": digest,
                    "reason": "already_published",
                })
                continue
            body, content_type = multipart(
                {"name": name, "sha256": digest, "run_id": context.run_id},
                {"artifact": (name, path.read_bytes(), _content_type(name))},
            )
            try:
                response = client.request(
                    "POST",
                    f"{endpoint}/api/v1/security-runs/{run_id}/artifacts",
                    headers=dict(headers, **{IDEMPOTENCY_HEADER: f"{context.run_id}:{name}"}),
                    body=body,
                    content_type=content_type,
                    idempotent=True,
                )
            except (HttpStatusError, HttpTransportError) as error:
                return self._failure(error, attempts, token)
            attempts.extend(response.attempts)
            uploaded += 1
            self.logger.info(self.log_step, "artifact_uploaded", {
                "service": self.service,
                "name": name,
                "sha256": digest,
            })

        try:
            completed = client.request(
                "POST",
                f"{endpoint}/api/v1/security-runs/{run_id}/complete",
                headers=dict(headers, **{IDEMPOTENCY_HEADER: f"{context.run_id}:complete"}),
                json_body={
                    "status": "SUCCESS",
                    "run_id": context.run_id,
                    "artifacts": names,
                    "checksums": checksums,
                    "result": self._result(context),
                },
                idempotent=True,
            )
        except (HttpStatusError, HttpTransportError) as error:
            return self._failure(error, attempts, token)
        attempts.extend(completed.attempts)

        self.logger.info(self.log_step, "publication_published", {
            "service": self.service,
            "run_id": context.run_id,
            "external_id": run_id,
            "uploaded": uploaded,
            "skipped": skipped,
        })
        return PublicationResult(
            service=self.service,
            status=PUBLISHED,
            external_ids={"run_id": run_id, "artifacts": uploaded + skipped},
            attempts=attempts,
            artifact="manifest.json",
            detail={"uploaded": uploaded, "skipped": skipped},
            required=self.required(),
        )

    # -- configuration -----------------------------------------------------
    def _connection(self):
        """Resolve endpoint and token, or return the PENDING result to publish."""
        endpoint_name = self.config.get(f"integrations.{self.service}.endpoint_env") or "endpoint"
        token_name = self.config.get(f"integrations.{self.service}.token_env") or "token"
        try:
            endpoint, token, _ = self.endpoint()
        except PublishError as error:
            return None, None, self._not_configured(
                endpoint_name, f"{endpoint_name} is not usable: {error}"
            )
        if not token:
            return None, None, self._not_configured(
                token_name,
                f"{token_name} is not set; {self.service} publication stays pending",
            )
        return endpoint, token, None

    def _not_configured(self, name, message):
        self.logger.warning(self.log_step, "publication_not_configured", {
            "service": self.service,
            "reason": "not_configured",
            "environment_variable": name,
        })
        return PublicationResult(
            service=self.service,
            status=PENDING,
            reason="not_configured",
            message=message,
            required=self.required(),
            detail={"deferred": True},
        )

    # -- payloads ----------------------------------------------------------
    def _run_payload(self, context):
        return {
            "run_id": context.run_id,
            "event": context.event,
            "project": context.project,
            "service": context.service,
            "version": context.version,
            "git": _mapping(context.git),
            "timestamps": _timestamps(context),
            "result": self._result(context),
            "decisions": _mapping((context.manifest or {}).get("decisions")),
        }

    def _result(self, context):
        return _mapping((context.manifest or {}).get("result"))

    def _artifact_path(self, context, name, source):
        if source == "report_path":
            return Path(context.report_path) if context.report_path else None
        if source == "sbom_path":
            return Path(context.sbom_path) if context.sbom_path else None
        return context.artifact(name) or (
            Path(context.run_dir) / name if context.run_dir else None
        )

    def _run_id(self, response):
        try:
            document = response.json()
        except ValueError:
            return None
        if not isinstance(document, dict):
            return None
        for key in ("id", "security_run_id"):
            value = document.get(key)
            if value not in (None, "", 0):
                return value
        return None

    def _known_artifacts(self, context):
        """Normalise the ledger record of artifacts already published for this run."""
        recorded = (context.known_external_ids or {}).get("artifacts")
        known = {}
        if isinstance(recorded, dict):
            for name, value in recorded.items():
                if isinstance(value, dict):
                    value = value.get("sha256") or value.get("checksum")
                if isinstance(value, str) and value:
                    known[name] = value
        elif isinstance(recorded, list):
            for entry in recorded:
                if isinstance(entry, dict) and entry.get("name") and entry.get("sha256"):
                    known[entry["name"]] = entry["sha256"]
        return known

    # -- outcome -----------------------------------------------------------
    def _failure(self, error, attempts, token):
        merged = list(attempts) + list(getattr(error, "attempts", None) or [])
        if isinstance(error, HttpStatusError):
            message = _redact(
                f"HTTP {error.status} rejected the publication: {error.snippet(limit=SNIPPET_LIMIT)}",
                [token],
            )
            if error.status >= 500:
                return self._deferred("server_error", message, merged)
            return self.fail("rejected", error=message, attempts=merged)
        message = _redact(
            f"transport error ({getattr(error, 'reason', 'unreachable')}) while publishing",
            [token],
        )
        return self._deferred("unreachable", message, merged)

    def _deferred(self, reason, message, attempts):
        self.logger.warning(self.log_step, "publication_deferred", {
            "service": self.service,
            "reason": reason,
            "message": message,
            "attempts": len(attempts),
        })
        return PublicationResult(
            service=self.service,
            status=PENDING,
            reason=reason,
            message=message,
            attempts=attempts,
            required=self.required(),
            detail={"deferred": True},
        )


__all__ = ("BaradDurPublisher",)

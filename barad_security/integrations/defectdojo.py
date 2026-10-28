"""Optional DefectDojo adapter: Trivy evidence import, never tickets.

Scope (S9): the runner imports the sanitised Trivy JSON report so DefectDojo holds
the evidence. It never converts findings into remediation tickets or tasks, and
pull-request imports are off unless the repository turns them on.

Identity is stable on purpose. The test title is derived from the service, the
event and the best available version/branch/commit reference, so re-running the
same execution targets the same DefectDojo test and updates it with `reimport`
instead of creating duplicates.
"""
from pathlib import Path

from ..errors import PublishError
from ..http import HttpStatusError, HttpTransportError, multipart
from .base import PENDING, PUBLISHED, PublicationResult, Publisher

REDACTED = "[REDACTED]"
SNIPPET_LIMIT = 200
SCAN_TYPE = "Trivy Scan"
TAGS = "barad-dur,trivy"
ARTIFACT_NAME = "trivy-report.json"


def _redact(text, secrets):
    """Strip known credential values from anything that may be persisted."""
    if not text:
        return text
    for secret in sorted({value for value in secrets if value}, key=len, reverse=True):
        text = text.replace(secret, REDACTED)
    return text


class DefectDojoPublisher(Publisher):
    service = "defectdojo"
    log_step = "publish"

    # -- entry point -------------------------------------------------------
    def publish(self, context):
        settings = self.settings()
        if not settings.get("publish_trivy_reports"):
            return self.skip("trivy_report_publication_disabled")
        if context.event == "pr" and not settings.get("publish_on_pull_request"):
            return self.skip("pull_request_import_disabled")
        report = Path(context.report_path) if context.report_path else None
        if report is None or not report.is_file():
            return self.skip("no_report")

        endpoint, token, problem = self._connection()
        if problem is not None:
            return problem

        title = self.test_title(context)
        known_test = (context.known_external_ids or {}).get("test")
        reimport = bool(settings.get("reimport", True)) and known_test not in (None, "", False)

        fields = {"scan_type": SCAN_TYPE}
        if reimport:
            fields["test"] = str(known_test)
            path = "/api/v2/reimport-scan/"
            mode = "reimport"
        else:
            path = "/api/v2/import-scan/"
            mode = "import"
        fields.update({
            "active": "true",
            "verified": "false",
            "close_old_findings": "false",
            "minimum_severity": settings.get("minimum_severity") or "Info",
            "test_title": title,
            "tags": TAGS,
            "commit_hash": _git_value(context, "commit_sha"),
            "branch_tag": _git_value(context, "branch"),
            "build_id": context.run_id,
            "environment": context.event,
        })
        if not reimport:
            fields["product_name"] = settings.get("product_name") or context.project
            fields["engagement_name"] = settings.get("engagement_name") or (
                f"{context.service or self.service} CI"
            )
            fields["auto_create_context"] = "false" if settings.get("auto_create_context") is False else "true"

        body, content_type = multipart(
            fields,
            {"file": (ARTIFACT_NAME, report.read_bytes(), "application/json")},
        )
        client = self.client()
        self.logger.info(self.log_step, "defectdojo_scan_submitted", {
            "service": self.service,
            "mode": mode,
            "test_title": title,
            "endpoint_path": path,
        })
        try:
            response = client.request(
                "POST",
                f"{endpoint}{path}",
                headers={"Authorization": f"Token {token}", "Accept": "application/json"},
                body=body,
                content_type=content_type,
            )
        except (HttpStatusError, HttpTransportError) as error:
            return self._failure(error, token)

        test_id = self._test_id(response)
        if test_id is None:
            return self._deferred(
                "server_error",
                "DefectDojo returned no test identifier",
                list(response.attempts),
            )

        self.logger.info(self.log_step, "publication_published", {
            "service": self.service,
            "mode": mode,
            "external_id": test_id,
            "test_title": title,
        })
        return PublicationResult(
            service=self.service,
            status=PUBLISHED,
            external_ids={"test": test_id},
            attempts=list(response.attempts),
            artifact=ARTIFACT_NAME,
            detail={"mode": mode, "test_title": title},
            required=self.required(),
        )

    # -- identity ----------------------------------------------------------
    def test_title(self, context):
        """Deterministic DefectDojo test name: prefix, service, event, reference."""
        prefix = (self.settings().get("test_title_prefix") or "").strip()
        reference = (
            context.version
            or (context.git or {}).get("branch")
            or ((context.git or {}).get("commit_sha") or "")[:12]
            or "unknown"
        )
        title = f"{context.service or self.service} {context.event} {reference}"
        return f"{prefix} {title}" if prefix else title

    # -- configuration -----------------------------------------------------
    def _connection(self):
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

    # -- response ----------------------------------------------------------
    def _test_id(self, response):
        try:
            document = response.json()
        except ValueError:
            return None
        if not isinstance(document, dict):
            return None
        value = document.get("test")
        if isinstance(value, dict):
            value = value.get("id")
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
        return None

    # -- outcome -----------------------------------------------------------
    def _failure(self, error, token):
        attempts = list(getattr(error, "attempts", None) or [])
        if isinstance(error, HttpStatusError):
            message = _redact(
                f"HTTP {error.status} rejected the import: {error.snippet(limit=SNIPPET_LIMIT)}",
                [token],
            )
            if error.status >= 500:
                return self._deferred("server_error", message, attempts)
            return self.fail("rejected", error=message, attempts=attempts)
        message = _redact(
            f"transport error ({getattr(error, 'reason', 'unreachable')}) while importing",
            [token],
        )
        return self._deferred("unreachable", message, attempts)

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


def _git_value(context, key):
    value = (context.git or {}).get(key)
    return value if value else None


__all__ = ("DefectDojoPublisher",)

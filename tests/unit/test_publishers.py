"""Publication adapters: BARAD-DÛR three-call contract and DefectDojo import.

Both adapters are exercised against a real HTTP server (`tests.support.MockServer`)
so the wire contract is what is asserted: paths, auth headers, idempotency keys,
multipart fields and file parts. No external API is contacted.
"""
import hashlib
import io
import json
import re
import tempfile
import unittest
from pathlib import Path

from barad_security.config import build_config
from barad_security.integrations.barad_dur import BaradDurPublisher
from barad_security.integrations.base import (
    FAILED,
    PENDING,
    PUBLISHED,
    SKIPPED,
    PublishContext,
)
from barad_security.integrations.defectdojo import DefectDojoPublisher
from barad_security.logs import Logger
from tests.support import MockServer

RUN_ID = "local-20260101T000000Z-abcdef"
BARAD_TOKEN = "token-value-123"
DOJO_TOKEN = "dojo-token-value"
BOUNDARY = b"----barad-dur-boundary"
ARTIFACT_NAMES = (
    "manifest.json",
    "decisions.json",
    "trivy-report.json",
    "sbom.cdx.json",
    "execution.log",
    "checksums.sha256",
)


def header(request, name):
    for key, value in request.headers.items():
        if key.lower() == name.lower():
            return value
    return None


def sha256_of(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def parse_multipart(body):
    """Split a multipart body into (fields, {name: (filename, bytes)})."""
    fields, files = {}, {}
    for chunk in body.split(b"--" + BOUNDARY)[1:]:
        if chunk.startswith(b"--"):
            break
        head, _, rest = chunk.partition(b"\r\n\r\n")
        content = rest[:-2] if rest.endswith(b"\r\n") else rest
        match = re.search(rb'name="([^"]+)"(?:; filename="([^"]+)")?', head)
        if not match:
            continue
        field_name = match.group(1).decode("utf-8")
        if match.group(2):
            files[field_name] = (match.group(2).decode("utf-8"), content)
        else:
            fields[field_name] = content.decode("utf-8")
    return fields, files


class PublisherTestCase(unittest.TestCase):
    """Shared fixture: one mock server, one temp evidence directory, one logger."""

    def setUp(self):
        self.server = MockServer().start()
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.files = {}
        for name in ARTIFACT_NAMES:
            path = self.root / name
            if name.endswith(".log"):
                path.write_text("log line\n", encoding="utf-8")
            else:
                path.write_text(json.dumps({"artifact": name}), encoding="utf-8")
            self.files[name] = path
        self.stream = io.StringIO()
        self.logger = Logger(RUN_ID, stream=self.stream)

    def tearDown(self):
        self.server.stop()
        self._tmp.cleanup()

    # -- builders ----------------------------------------------------------
    def environ(self):
        return {
            "BARAD_DUR_URL": self.server.url,
            "BARAD_DUR_TOKEN": BARAD_TOKEN,
            "DOJO_URL": self.server.url,
            "DOJO_TOKEN": DOJO_TOKEN,
        }

    def config(self, *, barad=None, dojo=None, environ=None):
        barad_settings = {"enabled": True}
        barad_settings.update(barad or {})
        dojo_settings = {"enabled": True, "publish_trivy_reports": True}
        dojo_settings.update(dojo or {})
        document = {
            "version": 1,
            "project": {"name": "OVAC", "service": "OVAC-Backend", "ecosystem": "node"},
            "integrations": {"barad_dur": barad_settings, "defectdojo": dojo_settings},
        }
        env = self.environ() if environ is None else dict(environ)
        return build_config(document, repo_root=self.root, environ=env)

    def context(self, **overrides):
        values = dict(
            run_id=RUN_ID,
            event="release",
            service="OVAC-Backend",
            project="OVAC",
            version="8.9.0",
            git={"branch": "main", "commit_sha": "a" * 40},
            run_dir=self.root,
            artifacts={name: self.files[name] for name in ARTIFACT_NAMES},
            manifest={
                "timestamps": {"started_at": "2026-01-01T00:00:00Z",
                               "finished_at": "2026-01-01T00:00:30Z"},
                "result": {"vulnerabilities": {"HIGH": 1, "LOW": 1}},
                "decisions": {"generate_sbom": True, "sbom_reason": "release_event"},
            },
            report_path=self.files["trivy-report.json"],
            raw_report_path=self.files["trivy-report.json"],
            sbom_path=self.files["sbom.cdx.json"],
        )
        values.update(overrides)
        return PublishContext(**values)


class BaradDurPublisherTests(PublisherTestCase):
    def routes_for_success(self, run_json=None):
        self.server.routes.update({
            "POST /api/v1/security-runs": (201, run_json or {"id": "run-99"}, {}),
            "POST /api/v1/security-runs/run-99/artifacts": (201, {"stored": True}, {}),
            "POST /api/v1/security-runs/run-99/complete": (200, {"status": "SUCCESS"}, {}),
        })

    def test_three_calls_in_order_with_artifacts(self):
        self.routes_for_success()
        context = self.context()
        result = BaradDurPublisher(self.config(), self.logger).publish(context)

        self.assertEqual(result.status, PUBLISHED)
        self.assertEqual(result.external_ids, {"run_id": "run-99", "artifacts": 6})
        self.assertEqual(result.artifact, "manifest.json")
        self.assertEqual(result.detail, {"uploaded": 6, "skipped": 0})
        self.assertTrue(result.required is False)

        paths = [request.path for request in self.server.requests]
        self.assertEqual(paths[0], "/api/v1/security-runs")
        self.assertEqual(paths[-1], "/api/v1/security-runs/run-99/complete")
        artifact_calls = [request for request in self.server.requests
                          if request.path.endswith("/artifacts")]
        self.assertEqual(len(artifact_calls), 6)

        created = self.server.requests[0]
        self.assertEqual(header(created, "Authorization"), f"Bearer {BARAD_TOKEN}")
        self.assertEqual(header(created, "Idempotency-Key"), RUN_ID)
        payload = created.json()
        for key in ("run_id", "event", "project", "service", "version", "git",
                    "timestamps", "result", "decisions"):
            self.assertIn(key, payload)
        self.assertEqual(payload["run_id"], RUN_ID)
        self.assertEqual(payload["service"], "OVAC-Backend")
        self.assertEqual(payload["result"], {"vulnerabilities": {"HIGH": 1, "LOW": 1}})

        uploaded = []
        for request in artifact_calls:
            self.assertEqual(header(request, "Authorization"), f"Bearer {BARAD_TOKEN}")
            fields, files = parse_multipart(request.body)
            self.assertIn("artifact", files)
            filename, content = files["artifact"]
            self.assertEqual(filename, fields["name"])
            self.assertEqual(fields["run_id"], RUN_ID)
            self.assertEqual(fields["sha256"], sha256_of(self.files[fields["name"]]))
            self.assertEqual(content, self.files[fields["name"]].read_bytes())
            self.assertEqual(header(request, "Idempotency-Key"), f"{RUN_ID}:{fields['name']}")
            uploaded.append(fields["name"])
        self.assertEqual(tuple(uploaded), ARTIFACT_NAMES)

        log_part = next(request for request in artifact_calls
                        if parse_multipart(request.body)[0]["name"] == "execution.log")
        self.assertIn("Content-Type: text/plain", log_part.body.decode("utf-8", "replace"))
        json_part = next(request for request in artifact_calls
                         if parse_multipart(request.body)[0]["name"] == "manifest.json")
        self.assertIn("Content-Type: application/json", json_part.body.decode("utf-8", "replace"))

        complete = self.server.requests[-1].json()
        self.assertEqual(complete["run_id"], RUN_ID)
        self.assertIn("status", complete)
        self.assertEqual(complete["artifacts"], list(ARTIFACT_NAMES))
        self.assertEqual(complete["checksums"]["manifest.json"],
                         sha256_of(self.files["manifest.json"]))
        self.assertEqual(complete["result"], {"vulnerabilities": {"HIGH": 1, "LOW": 1}})

    def test_security_run_id_alias_is_accepted(self):
        self.server.routes.update({
            "POST /api/v1/security-runs": (201, {"security_run_id": "sr-7"}, {}),
            "POST /api/v1/security-runs/sr-7/artifacts": (201, {}, {}),
            "POST /api/v1/security-runs/sr-7/complete": (200, {}, {}),
        })
        result = BaradDurPublisher(self.config(), self.logger).publish(self.context())
        self.assertEqual(result.status, PUBLISHED)
        self.assertEqual(result.external_ids["run_id"], "sr-7")

    def test_previously_published_artifacts_are_not_reuploaded(self):
        self.routes_for_success()
        known = {name: sha256_of(self.files[name]) for name in ARTIFACT_NAMES}
        context = self.context(known_external_ids={"artifacts": known})
        result = BaradDurPublisher(self.config(), self.logger).publish(context)
        self.assertEqual(result.status, PUBLISHED)
        self.assertEqual(result.detail, {"uploaded": 0, "skipped": 6})
        artifact_calls = [request for request in self.server.requests
                          if request.path.endswith("/artifacts")]
        self.assertEqual(artifact_calls, [])
        self.assertEqual(self.server.requests[-1].path,
                         "/api/v1/security-runs/run-99/complete")

    def test_missing_artifact_is_skipped_silently(self):
        self.routes_for_success()
        artifacts = dict(self.context().artifacts)
        artifacts.pop("sbom.cdx.json")
        context = self.context(artifacts=artifacts, sbom_path=None)
        result = BaradDurPublisher(self.config(), self.logger).publish(context)
        self.assertEqual(result.status, PUBLISHED)
        self.assertEqual(result.detail, {"uploaded": 5, "skipped": 0})
        complete = self.server.requests[-1].json()
        self.assertNotIn("sbom.cdx.json", complete["artifacts"])

    def test_503_defers_without_losing_evidence(self):
        self.server.routes["POST /api/v1/security-runs"] = (503, {"error": "maintenance"}, {})
        config = self.config(barad={"max_attempts": 2, "timeout_seconds": 2})
        result = BaradDurPublisher(config, self.logger).publish(self.context())

        self.assertEqual(result.status, PENDING)
        self.assertEqual(result.reason, "server_error")
        self.assertEqual(result.detail, {"deferred": True})
        self.assertEqual([attempt["status"] for attempt in result.attempts], [503, 503])
        self.assertTrue(all(path.exists() for path in self.files.values()))

    def test_400_is_a_rejection_with_bounded_snippet(self):
        self.server.routes["POST /api/v1/security-runs"] = (
            400, {"error": "invalid run payload"}, {})
        result = BaradDurPublisher(self.config(), self.logger).publish(self.context())

        self.assertEqual(result.status, FAILED)
        self.assertEqual(result.reason, "rejected")
        self.assertIn("400", result.message)
        self.assertIn("invalid run payload", result.message)
        self.assertNotIn(BARAD_TOKEN, json.dumps(result.public()))

    def test_missing_environment_is_pending_without_traffic(self):
        result = BaradDurPublisher(self.config(environ={}), self.logger).publish(self.context())

        self.assertEqual(result.status, PENDING)
        self.assertEqual(result.reason, "not_configured")
        self.assertIn("BARAD_DUR_URL", result.message)
        self.assertNotIn(BARAD_TOKEN, json.dumps(result.public()))
        self.assertEqual(self.server.requests, [])

    def test_missing_token_is_pending_and_names_the_variable(self):
        environ = self.environ()
        environ.pop("BARAD_DUR_TOKEN")
        result = BaradDurPublisher(self.config(environ=environ), self.logger).publish(self.context())
        self.assertEqual(result.status, PENDING)
        self.assertEqual(result.reason, "not_configured")
        self.assertIn("BARAD_DUR_TOKEN", result.message)
        self.assertEqual(self.server.requests, [])

    def test_required_flag_is_propagated(self):
        self.server.routes["POST /api/v1/security-runs"] = (500, {"error": "boom"}, {})
        config = self.config(barad={"required": True, "max_attempts": 1})
        result = BaradDurPublisher(config, self.logger).publish(self.context())
        self.assertEqual(result.status, PENDING)
        self.assertTrue(result.required)
        self.assertTrue(result.public()["required"])

    def test_transport_failure_is_pending(self):
        config = self.config(barad={"max_attempts": 1, "timeout_seconds": 1})
        config.environ["BARAD_DUR_URL"] = "http://127.0.0.1:9"
        result = BaradDurPublisher(config, self.logger).publish(self.context())
        self.assertEqual(result.status, PENDING)
        self.assertEqual(result.reason, "unreachable")
        self.assertEqual(len(result.attempts), 1)


class DefectDojoPublisherTests(PublisherTestCase):
    def import_routes(self, payload):
        self.server.routes["POST /api/v2/import-scan/"] = (201, payload, {})

    def test_import_sends_stable_identity_and_context(self):
        for payload in ({"test": 7}, {"test": {"id": 7}}):
            with self.subTest(payload=payload):
                self.server.requests.clear()
                self.server.routes.clear()
                self.import_routes(payload)
                result = DefectDojoPublisher(self.config(), self.logger).publish(self.context())

                self.assertEqual(result.status, PUBLISHED, result.message)
                self.assertEqual(result.external_ids, {"test": 7})
                self.assertEqual(result.artifact, "trivy-report.json")
                self.assertEqual(result.detail, {"mode": "import",
                                                 "test_title": "OVAC-Backend release 8.9.0"})
                self.assertEqual(len(self.server.requests), 1)
                request = self.server.requests[0]
                self.assertEqual(request.path, "/api/v2/import-scan/")
                self.assertEqual(header(request, "Authorization"), f"Token {DOJO_TOKEN}")

                fields, files = parse_multipart(request.body)
                self.assertEqual(fields["scan_type"], "Trivy Scan")
                self.assertEqual(fields["test_title"], "OVAC-Backend release 8.9.0")
                self.assertEqual(fields["active"], "true")
                self.assertEqual(fields["verified"], "false")
                self.assertEqual(fields["close_old_findings"], "false")
                self.assertEqual(fields["minimum_severity"], "Info")
                self.assertEqual(fields["tags"], "barad-dur,trivy")
                self.assertEqual(fields["commit_hash"], "a" * 40)
                self.assertEqual(fields["branch_tag"], "main")
                self.assertEqual(fields["build_id"], RUN_ID)
                self.assertEqual(fields["environment"], "release")
                self.assertEqual(fields["product_name"], "OVAC")
                self.assertEqual(fields["engagement_name"], "OVAC-Backend CI")
                self.assertEqual(fields["auto_create_context"], "true")
                self.assertNotIn("test", fields)
                self.assertIn("file", files)
                filename, content = files["file"]
                self.assertEqual(filename, "trivy-report.json")
                self.assertEqual(content, self.files["trivy-report.json"].read_bytes())

    def test_product_and_engagement_override_and_prefix(self):
        self.import_routes({"test": 3})
        config = self.config(dojo={"product_name": "OVAC Platform",
                                   "engagement_name": "Release 8.9.0",
                                   "test_title_prefix": "[barad]"})
        result = DefectDojoPublisher(config, self.logger).publish(self.context())
        fields, _ = parse_multipart(self.server.requests[0].body)
        self.assertEqual(fields["product_name"], "OVAC Platform")
        self.assertEqual(fields["engagement_name"], "Release 8.9.0")
        self.assertEqual(fields["test_title"], "[barad] OVAC-Backend release 8.9.0")
        self.assertEqual(result.detail["test_title"], "[barad] OVAC-Backend release 8.9.0")

    def test_test_title_falls_back_to_branch_then_commit_and_is_stable(self):
        publisher = DefectDojoPublisher(self.config(), self.logger)
        no_version = self.context(version=None)
        self.assertEqual(publisher.test_title(no_version), "OVAC-Backend release main")
        commit_only = self.context(version=None, git={"commit_sha": "1234567890abcdef"})
        self.assertEqual(publisher.test_title(commit_only), "OVAC-Backend release 1234567890ab")
        unknown = self.context(version=None, git={})
        self.assertEqual(publisher.test_title(unknown), "OVAC-Backend release unknown")
        self.assertEqual(publisher.test_title(unknown), publisher.test_title(unknown))

    def test_reimport_when_a_test_id_is_known(self):
        self.server.routes["POST /api/v2/reimport-scan/"] = (201, {"test": 42}, {})
        context = self.context(known_external_ids={"test": 42})
        result = DefectDojoPublisher(self.config(), self.logger).publish(context)

        self.assertEqual(result.status, PUBLISHED)
        self.assertEqual(result.external_ids, {"test": 42})
        self.assertEqual(result.detail["mode"], "reimport")
        self.assertEqual(len(self.server.requests), 1)
        request = self.server.requests[0]
        self.assertEqual(request.path, "/api/v2/reimport-scan/")
        fields, files = parse_multipart(request.body)
        self.assertEqual(fields["test"], "42")
        self.assertEqual(fields["scan_type"], "Trivy Scan")
        self.assertEqual(fields["test_title"], "OVAC-Backend release 8.9.0")
        self.assertEqual(fields["build_id"], RUN_ID)
        self.assertIn("file", files)

    def test_reimport_disabled_by_configuration_imports_again(self):
        self.import_routes({"test": 11})
        config = self.config(dojo={"reimport": False})
        context = self.context(known_external_ids={"test": 42})
        result = DefectDojoPublisher(config, self.logger).publish(context)
        self.assertEqual(result.detail["mode"], "import")
        self.assertEqual(self.server.requests[0].path, "/api/v2/import-scan/")

    def test_pull_request_import_is_skipped_by_default(self):
        self.import_routes({"test": 1})
        result = DefectDojoPublisher(self.config(), self.logger).publish(
            self.context(event="pr"))
        self.assertEqual(result.status, SKIPPED)
        self.assertEqual(result.reason, "pull_request_import_disabled")
        self.assertEqual(self.server.requests, [])

    def test_pull_request_publishes_when_enabled(self):
        self.import_routes({"test": 1})
        config = self.config(dojo={"publish_on_pull_request": True})
        result = DefectDojoPublisher(config, self.logger).publish(
            self.context(event="pr", version=None, git={"branch": "feat/x", "commit_sha": "b" * 40}))
        self.assertEqual(result.status, PUBLISHED)
        self.assertEqual(result.external_ids, {"test": 1})
        self.assertEqual(result.detail["test_title"], "OVAC-Backend pr feat/x")
        self.assertEqual(len(self.server.requests), 1)

    def test_disabled_report_publication_and_missing_report_are_skipped(self):
        disabled = DefectDojoPublisher(
            self.config(dojo={"publish_trivy_reports": False}), self.logger)
        result = disabled.publish(self.context())
        self.assertEqual(result.status, SKIPPED)
        self.assertEqual(result.reason, "trivy_report_publication_disabled")

        missing = DefectDojoPublisher(self.config(), self.logger).publish(
            self.context(report_path=None))
        self.assertEqual(missing.status, SKIPPED)
        self.assertEqual(missing.reason, "no_report")
        self.assertEqual(self.server.requests, [])

    def test_500_defers_and_400_is_rejected(self):
        self.server.routes["POST /api/v2/import-scan/"] = (500, {"error": "server down"}, {})
        config = self.config(dojo={"max_attempts": 1})
        pending = DefectDojoPublisher(config, self.logger).publish(self.context())
        self.assertEqual(pending.status, PENDING)
        self.assertEqual(pending.reason, "server_error")
        self.assertEqual(pending.detail, {"deferred": True})
        self.assertEqual([attempt["status"] for attempt in pending.attempts], [500])

        self.server.routes["POST /api/v2/import-scan/"] = (400, {"error": "bad product"}, {})
        rejected = DefectDojoPublisher(config, self.logger).publish(self.context())
        self.assertEqual(rejected.status, FAILED)
        self.assertEqual(rejected.reason, "rejected")
        self.assertIn("400", rejected.message)
        self.assertIn("bad product", rejected.message)
        self.assertNotIn(DOJO_TOKEN, json.dumps(rejected.public()))

    def test_missing_environment_is_pending(self):
        result = DefectDojoPublisher(self.config(environ={}), self.logger).publish(self.context())
        self.assertEqual(result.status, PENDING)
        self.assertEqual(result.reason, "not_configured")
        self.assertIn("DOJO_URL", result.message)
        self.assertEqual(self.server.requests, [])


class RedactionTests(PublisherTestCase):
    def test_tokens_never_reach_results_or_logs(self):
        self.server.routes["POST /api/v1/security-runs"] = (
            400, {"error": f"bad bearer {BARAD_TOKEN}"}, {})
        self.server.routes["POST /api/v2/import-scan/"] = (
            400, {"error": f"bad token {DOJO_TOKEN}"}, {})

        barad = BaradDurPublisher(self.config(), self.logger).publish(self.context())
        dojo = DefectDojoPublisher(self.config(), self.logger).publish(self.context())

        for result, token in ((barad, BARAD_TOKEN), (dojo, DOJO_TOKEN)):
            self.assertEqual(result.status, FAILED)
            self.assertNotIn(token, json.dumps(result.public()))
            self.assertIn("[REDACTED]", result.message)
        logs = self.stream.getvalue()
        self.assertNotIn(BARAD_TOKEN, logs)
        self.assertNotIn(DOJO_TOKEN, logs)


if __name__ == "__main__":
    unittest.main()

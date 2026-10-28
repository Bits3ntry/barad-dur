"""Dependency-Track adapter: projects, releases, history and deferred failures."""
import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from barad_security.config import build_config
from barad_security.integrations import base as pub
from barad_security.integrations.dependency_track import DependencyTrackPublisher
from barad_security.logs import Logger
from tests.support import TRIVY_SBOM_TEMPLATE, MockServer


class DependencyTrackTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.run_dir = Path(self._tmp.name)
        self.sbom_path = self.run_dir / "sbom.cdx.json"
        self.sbom_path.write_text(json.dumps(TRIVY_SBOM_TEMPLATE), encoding="utf-8")
        self.sbom_bytes = self.sbom_path.read_bytes()
        self.sbom_sha = hashlib.sha256(self.sbom_bytes).hexdigest()
        self.server = MockServer().start()
        self.log_stream = __import__("io").StringIO()
        self.logger = Logger("run-1", stream=self.log_stream,
                             redactor=__import__("barad_security.logs", fromlist=["Redactor"]).Redactor(["dt-api-key-value"]))
        self.environ = {"DTRACK_URL": self.server.url, "DTRACK_API_KEY": "dt-api-key-value"}

    def tearDown(self):
        self.server.stop()
        self._tmp.cleanup()

    def publisher(self, **overrides):
        settings = {"enabled": True, "publish_on_release": True, "auto_create": True}
        settings.update(overrides)
        config = build_config(
            {"version": 1,
             "project": {"name": "OVAC", "service": "OVAC-Backend", "ecosystem": "node",
                         "version": {"source": "package-json"}},
             "integrations": {"dependency_track": settings}},
            repo_root=self.run_dir, environ=self.environ)
        return DependencyTrackPublisher(config, self.logger)

    def context(self, *, event="release", version="8.9.0", target="release", known=None):
        return pub.PublishContext(
            run_id="local-1", event=event, service="OVAC-Backend", project="OVAC",
            version=version, git={"commit_sha": "a" * 40, "branch": "main"},
            run_dir=self.run_dir, sbom_path=self.sbom_path,
            publish_target=target, required=False,
            known_external_ids=dict(known or {}))

    def project_fixture(self, uuid="11111111-1111-1111-1111-111111111111"):
        return {"uuid": uuid, "name": "OVAC-Backend", "version": "8.9.0"}

    def test_release_publishes_to_the_resolved_project(self):
        self.server.routes["GET /api/v1/project"] = (200, [self.project_fixture()], {})
        self.server.routes["PUT /api/v1/bom"] = (200, {"token": "processing-token"}, {})
        result = self.publisher().publish(self.context())
        self.assertEqual(result.status, pub.PUBLISHED)
        self.assertEqual(result.external_ids["project"], "11111111-1111-1111-1111-111111111111")
        self.assertEqual(result.external_ids["token"], "processing-token")
        bom_request = [request for request in self.server.requests if request.path == "/api/v1/bom"][0]
        body = bom_request.json()
        self.assertEqual(body["project"], "11111111-1111-1111-1111-111111111111")
        self.assertEqual(base64.b64decode(body["bom"]), self.sbom_bytes)
        self.assertEqual(bom_request.headers["X-Api-Key"], "dt-api-key-value")
        self.assertNotIn("Authorization", bom_request.headers)

    def test_missing_project_is_created_only_when_allowed(self):
        self.server.routes["GET /api/v1/project"] = (200, [], {})
        self.server.routes["PUT /api/v1/project"] = (200, {"uuid": "new-project-uuid"}, {})
        self.server.routes["PUT /api/v1/bom"] = (200, {"token": "t"}, {})
        result = self.publisher().publish(self.context())
        self.assertEqual(result.status, pub.PUBLISHED)
        creation = [request for request in self.server.requests if request.path == "/api/v1/project"
                    and request.method == "PUT"][0]
        self.assertEqual(creation.json(), {"name": "OVAC-Backend", "version": "8.9.0", "active": True})
        self.assertIn("project_created", self.log_stream.getvalue())

    def test_missing_project_without_auto_create_fails_without_uploading(self):
        self.server.routes["GET /api/v1/project"] = (200, [], {})
        result = self.publisher(auto_create=False).publish(self.context())
        self.assertEqual(result.status, pub.FAILED)
        self.assertEqual(result.reason, "project_missing")
        self.assertFalse([request for request in self.server.requests if request.path == "/api/v1/bom"])

    def test_identical_release_sbom_is_not_published_twice(self):
        known = {"release_sbom_sha256": self.sbom_sha, "sbom_sha256": self.sbom_sha}
        result = self.publisher().publish(self.context(known=known))
        self.assertEqual(result.status, pub.DUPLICATE)
        self.assertEqual(result.reason, "unchanged_release_inventory")
        self.assertEqual(self.server.requests, [])

    def test_conflicting_release_inventory_is_reported_not_overwritten(self):
        known = {"release_sbom_sha256": "f" * 64, "sbom_sha256": self.sbom_sha,
                 "release_component_fingerprint": "different"}
        result = self.publisher().publish(self.context(known=known))
        self.assertEqual(result.status, pub.FAILED)
        self.assertEqual(result.reason, "release_inventory_conflict")
        self.assertEqual(self.server.requests, [])
        self.assertIn("release_inventory_conflict", self.log_stream.getvalue())

    def test_explicit_opt_in_allows_replacing_a_release_inventory(self):
        self.server.routes["GET /api/v1/project"] = (200, [self.project_fixture()], {})
        self.server.routes["PUT /api/v1/bom"] = (200, {"token": "t"}, {})
        known = {"release_sbom_sha256": "f" * 64, "sbom_sha256": self.sbom_sha,
                 "release_component_fingerprint": "different"}
        result = self.publisher(allow_release_overwrite=True).publish(self.context(known=known))
        self.assertEqual(result.status, pub.PUBLISHED)
        self.assertIn("release_inventory_replaced", self.log_stream.getvalue())

    def test_mutable_release_version_is_refused(self):
        for version in ("latest", "main", "", "  "):
            result = self.publisher().publish(self.context(version=version))
            self.assertEqual(result.status, pub.FAILED)
            self.assertEqual(result.reason, "invalid_release_identity")
        self.assertEqual(self.server.requests, [])

    def test_server_error_defers_publication_without_losing_evidence(self):
        self.server.routes["GET /api/v1/project"] = (200, [self.project_fixture()], {})
        self.server.enqueue("PUT /api/v1/bom", (503, {"error": "down"}, {}),
                            (503, {"error": "down"}, {}), (503, {"error": "down"}, {}))
        result = self.publisher().publish(self.context())
        self.assertEqual(result.status, pub.PENDING)
        self.assertEqual(result.reason, "server_error")
        self.assertTrue(result.detail["deferred"])
        self.assertTrue(len(result.attempts) >= 1)
        self.assertTrue(self.sbom_path.is_file())

    def test_unauthorized_is_a_failure_not_a_retry(self):
        self.server.routes["GET /api/v1/project"] = (401, {"error": "bad key"}, {})
        result = self.publisher().publish(self.context())
        self.assertEqual(result.status, pub.FAILED)
        self.assertEqual(result.reason, "unauthorized")

    def test_wait_for_analysis_polls_the_token_endpoint(self):
        self.server.routes["GET /api/v1/project"] = (200, [self.project_fixture()], {})
        self.server.routes["PUT /api/v1/bom"] = (200, {"token": "tok"}, {})
        self.server.enqueue("GET /api/v1/bom/token/tok", (200, {"processing": True}, {}),
                            (200, {"processing": False}, {}))
        result = self.publisher(wait_for_analysis=True, wait_timeout_seconds=2).publish(self.context())
        self.assertEqual(result.status, pub.PUBLISHED)
        self.assertTrue(result.detail["wait_for_analysis"])
        polls = [request for request in self.server.requests if request.path.startswith("/api/v1/bom/token/")]
        self.assertEqual(len(polls), 2)

    def test_latest_is_never_promoted_by_default(self):
        self.server.routes["GET /api/v1/project"] = (200, [self.project_fixture()], {})
        self.server.routes["PUT /api/v1/bom"] = (200, {"token": "t"}, {})
        result = self.publisher().publish(self.context())
        self.assertEqual(result.status, pub.PUBLISHED)
        self.assertFalse(result.detail["latest"])
        self.assertFalse([request for request in self.server.requests
                          if request.method == "POST" and request.path == "/api/v1/project"])

    def test_development_publication_uses_the_development_version(self):
        self.server.routes["GET /api/v1/project"] = (200, [{"uuid": "dev-uuid", "name": "OVAC-Backend",
                                                           "version": "main"}], {})
        self.server.routes["PUT /api/v1/bom"] = (200, {"token": "t"}, {})
        result = self.publisher(update_development_project=True).publish(
            self.context(event="push", version="8.9.0", target="development"))
        self.assertEqual(result.status, pub.PUBLISHED)
        self.assertEqual(result.detail["version"], "main")
        lookup = self.server.requests[0]
        self.assertIn("version=main", lookup.path)

    def test_not_configured_names_the_environment_variable(self):
        config = build_config(
            {"version": 1, "project": {"name": "OVAC", "service": "OVAC-Backend", "ecosystem": "node"},
             "integrations": {"dependency_track": {"enabled": True}}},
            repo_root=self.run_dir, environ={})
        result = DependencyTrackPublisher(config, self.logger).publish(self.context())
        self.assertEqual(result.status, pub.PENDING)
        self.assertEqual(result.reason, "not_configured")
        self.assertIn("DTRACK_URL", result.message)
        self.assertEqual(self.server.requests, [])

    def test_token_never_appears_in_the_result(self):
        self.server.routes["GET /api/v1/project"] = (200, [self.project_fixture()], {})
        self.server.routes["PUT /api/v1/bom"] = (400, {"error": "bad key dt-api-key-value"}, {})
        result = self.publisher().publish(self.context())
        self.assertEqual(result.status, pub.FAILED)
        self.assertNotIn("dt-api-key-value", json.dumps(result.public()))
        self.assertNotIn("dt-api-key-value", self.log_stream.getvalue())


if __name__ == "__main__":
    unittest.main()

"""Configuration contract: schema errors, environment expansion, safe paths."""
import json
import tempfile
import unittest
from pathlib import Path

from barad_security.config import build_config, load_config
from barad_security.errors import ConfigError

REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = REPO_ROOT / "config" / "barad-security.example.yml"


def minimal(**overrides):
    document = {
        "version": 1,
        "project": {"name": "OVAC", "service": "OVAC-Backend", "ecosystem": "node", "path": "."},
    }
    document.update(overrides)
    return document


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name)
        (self.repo / "package.json").write_text(json.dumps({"name": "demo", "version": "1.0.0"}), encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def build(self, document, environ=None):
        return build_config(document, repo_root=self.repo, environ=environ or {})

    def test_example_configuration_is_valid(self):
        config = load_config(EXAMPLE, repo_root=REPO_ROOT, environ={})
        self.assertEqual(config.get("project.service"), "OVAC-Backend")
        self.assertEqual(config.get("trivy.scan_type"), "fs")
        self.assertEqual(config.get("sbom.generator"), "trivy")

    def test_unknown_key_is_rejected_with_its_path(self):
        document = minimal()
        document["trivy"] = {"scanners": ["vuln"], "scanner": ["secret"]}
        with self.assertRaises(ConfigError) as caught:
            self.build(document)
        message = str(caught.exception)
        self.assertIn("invalid configuration", message)
        self.assertIn("trivy", message)
        self.assertIn("scanner", message)

    def test_empty_service_is_rejected_without_scanning(self):
        document = minimal()
        document["project"] = {"name": "OVAC", "service": "   "}
        with self.assertRaises(ConfigError):
            self.build(document)

    def test_trivy_can_never_be_disabled(self):
        with self.assertRaises(ConfigError) as caught:
            self.build(minimal(trivy={"enabled": False}))
        self.assertIn("trivy.enabled", str(caught.exception))
        with self.assertRaises(ConfigError) as caught:
            self.build(minimal(trivy={"always_run": False}))
        self.assertIn("always_run", str(caught.exception))

    def test_non_trivy_generator_is_rejected(self):
        with self.assertRaises(ConfigError) as caught:
            self.build(minimal(sbom={"generator": "syft"}))
        self.assertIn("sbom.generator", str(caught.exception))

    def test_absolute_and_escaping_paths_are_rejected(self):
        for value in ("/etc", "../outside", "sub/../../outside"):
            with self.assertRaises(ConfigError):
                self.build(minimal(artifacts={"directory": value}))

    def test_undefined_environment_variable_is_reported_by_path(self):
        with self.assertRaises(ConfigError) as caught:
            self.build(minimal(integrations={"barad_dur": {"endpoint_env": "${BARAD_DUR_MISSING_VAR}"}}), environ={})
        self.assertIn("BARAD_DUR_MISSING_VAR", str(caught.exception))

    def test_environment_expansion_and_defaults(self):
        config = self.build(
            minimal(project={"name": "OVAC", "service": "OVAC-Backend", "ecosystem": "node", "path": "."},
                    detection={"base_ref": "${BASE_REF:-main}"}),
            environ={},
        )
        self.assertEqual(config.get("detection.base_ref"), "main")
        config = self.build(minimal(), environ={})
        self.assertIsNone(config.get("detection.base_ref"))

    def test_environment_values_keep_their_yaml_type(self):
        document = minimal(integrations={"dependency_track": {"enabled": "${DTRACK_ON:-false}"}})
        self.assertIs(self.build(document, environ={}).get("integrations.dependency_track.enabled"), False)
        self.assertIs(self.build(document, environ={"DTRACK_ON": "true"}).get(
            "integrations.dependency_track.enabled"), True)
        document = minimal(trivy={"timeout_seconds": "${SEC_TIMEOUT:-900}"})
        self.assertEqual(self.build(document, environ={}).get("trivy.timeout_seconds"), 900)

    def test_credentials_are_referenced_by_name_only(self):
        config = self.build(minimal())
        document = config.public()
        text = json.dumps(document)
        self.assertIn("DTRACK_API_KEY", text)          # the variable name
        self.assertNotIn("X-Api-Key", text)            # never a header value
        self.assertEqual(config.fingerprint(), self.build(minimal()).fingerprint())

    def test_shell_metacharacters_are_refused(self):
        for value in ("vuln;rm -rf /", "vuln&&whoami", "vuln|tee /tmp/x", "$(id)"):
            with self.assertRaises(ConfigError):
                self.build(minimal(trivy={"scanners": [value]}))

    def test_image_target_requires_a_target(self):
        with self.assertRaises(ConfigError) as caught:
            self.build(minimal(trivy={"scan_type": "image"}))
        self.assertIn("trivy.target", str(caught.exception))

    def test_unimplemented_slack_is_rejected_loudly(self):
        with self.assertRaises(ConfigError) as caught:
            self.build(minimal(notifications={"direct_slack": True}))
        self.assertIn("not implemented", str(caught.exception))

    def test_release_publishing_requires_sbom(self):
        with self.assertRaises(ConfigError) as caught:
            self.build(minimal(sbom={"enabled": False},
                               integrations={"dependency_track": {"enabled": True, "publish_on_release": True}}))
        self.assertIn("sbom.enabled", str(caught.exception))

    def test_version_source_requirements(self):
        with self.assertRaises(ConfigError) as caught:
            self.build(minimal(project={"name": "OVAC", "service": "OVAC-Backend",
                                        "ecosystem": "node", "path": ".",
                                        "version": {"source": "literal"}}))
        self.assertIn("project.version.value", str(caught.exception))

    def test_missing_configuration_file_is_an_explicit_error(self):
        with self.assertRaises(ConfigError) as caught:
            load_config(repo_root=self.repo, environ={})
        self.assertIn("barad-security.yml", str(caught.exception))

    def test_patterns_cannot_escape_the_repository(self):
        with self.assertRaises(ConfigError):
            self.build(minimal(sbom={"include_patterns": ["../**/package.json"]}))


if __name__ == "__main__":
    unittest.main()

import json
import os
import unittest
from pathlib import Path
from unittest import mock

from cli_support import CliTestCase, FakeTrivy


class ConfigurationTests(CliTestCase):
    def test_defaults_are_secure_without_a_config_file(self):
        from barad.config import load_settings

        settings = load_settings(
            {},
            source=None,
            root=self.root,
            project_name="demo",
            ecosystems=(),
            environ={},
        )

        self.assertEqual(settings.security.get("trivy.runner"), "docker")
        self.assertEqual(settings.security.get("trivy.scan_type"), "fs")
        self.assertEqual(settings.security.get("artifacts.directory"), ".barad/reports")
        self.assertEqual(settings.document["output"]["directory"], ".barad/reports")
        for block in ("dependency_track", "defectdojo"):
            self.assertFalse(settings.document["integrations"][block]["enabled"])
            self.assertIn("endpoint_env", settings.document["integrations"][block])
            self.assertIn("token_env", settings.document["integrations"][block])

    def test_unknown_configuration_key_is_rejected(self):
        self.write_config("version: 1\nscan:\n  danger: true\n")

        code, out, err = self.invalid_scan()

        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err, "error: unknown configuration key: scan.danger\n")

    def test_malformed_scan_list_is_rejected(self):
        self.write_config("version: 1\nscan:\n  exclude_paths: vendor\n")

        code, out, err = self.invalid_scan()

        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(
            err,
            "error: invalid configuration: scan.exclude_paths must be a list of non-empty strings\n",
        )

    def test_output_overlapping_state_is_rejected(self):
        self.write_config("version: 1\noutput:\n  directory: .barad/state\n")

        code, out, err = self.invalid_scan()

        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(
            err,
            "error: invalid configuration: output.directory must not overlap "
            "the state directory: .barad/state\n",
        )

    def test_secret_value_in_config_is_rejected_without_echoing_it(self):
        self.write_config(
            "version: 1\nintegrations:\n  dependency_track:\n    token: super-secret-value\n"
        )

        code, out, err = self.invalid_scan()

        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(
            err,
            "error: refusing secret value at integrations.dependency_track.token; "
            "declare an environment variable name with token_env instead\n",
        )
        self.assertNotIn("super-secret-value", err)

    def test_barad_yml_overrides_defaults(self):
        self.write_config(
            "version: 1\n"
            "project:\n  name: custom-project\n"
            "scan:\n  runner: local\n  exclude_paths:\n    - vendor\n"
            "output:\n  directory: reports\n"
        )

        code, out, err, manifest, run_dir = self.scan(
            cwd=self.root, output=self.root / "reports"
        )

        self.assertEqual(code, 0, err)
        self.assertEqual(manifest["project"]["name"], "custom-project")
        self.assertEqual(manifest["project"]["name_source"], "config")
        self.assertEqual(manifest["config"]["source"], ".barad.yml")
        from test_scan_contract import evidence_parent
        self.assertEqual(run_dir.parent, evidence_parent(manifest, self.root / "reports").resolve())
        self.assertEqual(run_dir.name, manifest["run"]["id"])
        self.assertEqual(run_dir.parent.parent.parent, (self.root / "reports").resolve())
        self.assertTrue(self.state_path.is_file())
        self.assertEqual(FakeTrivy.instances[-1].config.get("trivy.runner"), "local")
        self.assertEqual(FakeTrivy.instances[-1].config.exclude_paths(), ["vendor"])

    def test_output_flag_wins_over_configured_directory(self):
        self.write_config("version: 1\noutput:\n  directory: reports\n")

        code, out, err, manifest, run_dir = self.scan(
            "--output", "./out2", cwd=self.root, output=self.root / "out2"
        )

        self.assertEqual(code, 0, err)
        from test_scan_contract import evidence_parent
        self.assertEqual(run_dir.parent, evidence_parent(manifest, self.root / "out2").resolve())
        self.assertEqual(run_dir.name, manifest["run"]["id"])
        self.assertFalse((self.root / "reports").exists())
        self.assertTrue(self.state_path.is_file())

    def test_image_target_comes_from_config_and_rejects_positional_path(self):
        self.write_config(
            "version: 1\n"
            "project:\n  name: image-project\n"
            "scan:\n"
            "  target_type: image\n"
            "  target: ghcr.io/acme/app@sha256:abc123\n"
            "  runner: local\n"
        )

        code, out, err, manifest, run_dir = self.scan(cwd=self.root)

        self.assertEqual(code, 0, err)
        self.assertEqual(manifest["project"]["target"]["type"], "image")
        self.assertEqual(
            manifest["project"]["target"]["value"], "ghcr.io/acme/app@sha256:abc123"
        )
        self.assertEqual(FakeTrivy.instances[-1].scan_type, "image")

        code, out, err, manifest, run_dir = self.scan(".", cwd=self.root)
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(
            err,
            "error: image scanning is configured; omit the positional path or remove "
            "scan.target_type: image from .barad.yml\n",
        )

    def test_environment_overrides_endpoint_and_never_leaks_the_token(self):
        from barad.config import load_settings, read_project_config

        config = self.write_config(
            "version: 1\n"
            "integrations:\n"
            "  dependency_track:\n"
            "    endpoint: https://dt.file\n"
            "    endpoint_env: DTRACK_URL\n"
            "    token_env: DTRACK_API_KEY\n"
        )
        environ = {
            "DTRACK_URL": "https://dt.env",
            "DTRACK_API_KEY": "supersecret123",
        }
        document, source = read_project_config(config)
        settings = load_settings(
            document,
            source=source,
            root=self.root,
            project_name="demo",
            ecosystems=(),
            environ=environ,
        )

        self.assertEqual(settings.endpoint("dependency_track"), "https://dt.env")
        self.assertTrue(settings.connection("dependency_track")["token_configured"])
        self.assertNotIn("supersecret123", json.dumps(settings.public()))

        with mock.patch.dict(os.environ, environ, clear=False):
            code, out, err, manifest, run_dir = self.scan(cwd=self.root)

        self.assertEqual(code, 0, err)
        self.assertNotIn("supersecret123", out)
        self.assertNotIn("supersecret123", err)
        for path in run_dir.rglob("*"):
            if path.is_file():
                self.assertNotIn("supersecret123", path.read_text(encoding="utf-8", errors="ignore"))

    def invalid_scan(self):
        with mock.patch("barad.scan.TrivyRunner", FakeTrivy):
            from cli_support import invoke

            return invoke(["scan"], cwd=self.root)


if __name__ == "__main__":
    unittest.main()

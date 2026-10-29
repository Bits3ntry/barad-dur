import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from barad.core.trivy import TrivyRunner


class Config:
    def get(self, key, default=None):
        values = {
            "trivy.runner": "local",
            "trivy.executable": "trivy",
            "trivy.image": "aquasec/trivy:0.76.1",
            "trivy.scanners": ["vuln", "secret", "misconfig"],
            "trivy.severity": ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
            "trivy.timeout_seconds": 30,
            "trivy.cache_enabled": False,
            "trivy.scan_type": "fs",
            "project.path": ".",
        }
        return values.get(key, default)

    def exclude_paths(self):
        return []


class EmptyTrivyResultTests(unittest.TestCase):
    def test_valid_trivy_report_without_results_is_a_successful_empty_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "security.json"
            runner = TrivyRunner(Config(), None, repo_root=directory)

            def execute(**_kwargs):
                output.write_text(json.dumps({
                    "SchemaVersion": 2,
                    "ArtifactName": "/scan",
                    "ArtifactType": "filesystem",
                    "Trivy": {"Version": "0.76.1"},
                }), encoding="utf-8")
                return ["trivy"], None, 0, "", ""

            with mock.patch.object(runner, "_execute", side_effect=execute), \
                 mock.patch.object(runner, "version", return_value="0.76.1"):
                outcome = runner.scan_json(output)

        self.assertTrue(outcome.successful)
        self.assertEqual(outcome.counts["results"], 0)
        self.assertIn("trivy_reported_no_targets", outcome.warnings)


if __name__ == "__main__":
    unittest.main()

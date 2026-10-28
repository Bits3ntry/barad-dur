"""Black-box tests for the public catalog validation command."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "catalog" / "validate.py"


def run_catalog(document):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "catalog.yaml"
        path.write_text(json.dumps(document), encoding="utf-8")  # JSON is YAML 1.2.
        return subprocess.run([sys.executable, str(CLI), str(path)], capture_output=True, text=True)


class CatalogCliTests(unittest.TestCase):
    def test_shared_service_and_immutable_release_are_valid(self):
        doc = {
            "products": [
                {"id": "product-a", "name": "A", "description": "demo", "owner": "team-a", "criticality": "medium", "lifecycle": "active", "services": ["shared"]},
                {"id": "product-b", "name": "B", "description": "demo", "owner": "team-b", "criticality": "low", "lifecycle": "active", "services": ["shared"]},
            ],
            "services": [{"id": "shared", "name": "Shared", "owner": "team-a", "kind": "internal", "releases": [{"version": "1.0.0", "commit": "a" * 40, "date": "2026-01-01", "build": "ci-1", "sboms": []}], "deployments": [{"environment": "staging", "release": "1.0.0", "deployed_at": "2026-01-02T00:00:00Z", "infrastructure": "demo"}]}],
            "relationships": [],
        }
        result = run_catalog(doc)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "valid catalog\n", ""))

    def test_mutable_latest_release_is_rejected(self):
        release = {"version": "latest", "commit": "a" * 40, "date": "2026-01-01", "build": "ci-1", "sboms": []}
        doc = {"products": [], "services": [{"id": "app", "name": "App", "owner": "team", "kind": "internal", "releases": [release], "deployments": []}], "relationships": []}
        result = run_catalog(doc)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("latest", result.stderr)
        self.assertEqual(release["version"], "latest")
        release["version"] = "latest\n"
        newline = run_catalog(doc)
        self.assertEqual(newline.returncode, 1)
        self.assertEqual(newline.stdout, "")
        self.assertIn("latest", newline.stderr)

    def test_invalid_reference_rejected_without_mutation(self):
        doc = {"products": [{"id": "p", "name": "P", "description": "demo", "owner": "t", "criticality": "low", "lifecycle": "active", "services": ["missing"]}], "services": [], "relationships": []}
        result = run_catalog(doc)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("missing", result.stderr)
        # The CLI is read-only; the file and its counters remain the caller's source of truth.
        self.assertEqual(doc["products"][0]["services"], ["missing"])


if __name__ == "__main__":
    unittest.main()

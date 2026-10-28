"""CycloneDX validation and the evidence store contract."""
import json
import tempfile
import unittest
from pathlib import Path

from barad_security import sbom
from barad_security.config import build_config
from barad_security.evidence import RunStore, generate_run_id, sha256_file
from tests.support import TRIVY_SBOM_TEMPLATE


def clone():
    return json.loads(json.dumps(TRIVY_SBOM_TEMPLATE))


class SbomValidationTests(unittest.TestCase):
    def test_valid_inventory_is_summarised(self):
        result = sbom.validate(clone())
        self.assertTrue(result.ok, result.problems)
        self.assertEqual(result.summary["bom_format"], "CycloneDX")
        self.assertEqual(result.summary["components"], 2)
        self.assertEqual(result.summary["components_with_purl"], 2)
        self.assertEqual(result.summary["dependency_relations"], 2)
        self.assertIn("trivy", result.summary["generator"])

    def test_missing_format_and_components_are_problems(self):
        document = clone()
        del document["bomFormat"]
        document["components"] = []
        result = sbom.validate(document)
        self.assertFalse(result.ok)
        codes = {problem["code"] for problem in result.problems}
        self.assertIn("sbom_bom_format", codes)
        self.assertIn("sbom_components_missing", codes)

    def test_missing_dependency_graph_is_a_quality_warning(self):
        document = clone()
        document.pop("dependencies")
        result = sbom.validate(document)
        self.assertTrue(result.ok)
        codes = {warning["code"] for warning in result.warnings}
        self.assertIn("sbom_dependency_graph_missing", codes)

    def test_vulnerability_results_inside_the_inventory_are_flagged(self):
        document = clone()
        document["vulnerabilities"] = [{"id": "CVE-2021-23337"}]
        result = sbom.validate(document)
        codes = {warning["code"] for warning in result.warnings}
        self.assertIn("sbom_contains_vulnerabilities", codes)

    def test_unsupported_spec_version_is_a_problem(self):
        document = clone()
        document["specVersion"] = "2.0"
        result = sbom.validate(document)
        self.assertFalse(result.ok)
        self.assertEqual(result.problems[0]["code"], "sbom_spec_version_unsupported")

    def test_non_object_root_is_rejected(self):
        self.assertFalse(sbom.validate(["not", "a", "document"]).ok)


class EvidenceStoreTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name)
        self.config = build_config(
            {"version": 1, "project": {"name": "OVAC", "service": "OVAC-Backend", "ecosystem": "node"}},
            repo_root=self.repo, environ={})
        self.store = RunStore(self.config, "local-20260101T000000Z-abcdef").prepare()

    def tearDown(self):
        self._tmp.cleanup()

    def test_layout_and_atomic_json(self):
        path = self.store.write_json("decisions.json", {"generate_sbom": True})
        self.assertEqual(path.parent.resolve(),
                         (self.repo / ".barad-dur" / "security" / "runs" / "local-20260101T000000Z-abcdef").resolve())
        self.assertTrue(json.loads(path.read_text())["generate_sbom"])
        self.assertTrue((self.repo / ".barad-dur" / "security" / "state").is_dir())
        self.assertTrue((self.repo / ".barad-dur" / "security" / "pending").is_dir())

    def test_checksums_are_sha256sum_compatible(self):
        self.store.write_text("trivy-report.json", '{"Results": []}\n')
        self.store.write_text("decisions.json", "{}\n")
        entries = self.store.write_checksums(["trivy-report.json", "decisions.json"])
        lines = self.store.artifact_path("checksums.sha256").read_text().splitlines()
        self.assertEqual(len(lines), 2)
        for line in lines:
            digest, name = line.split("  ")
            self.assertEqual(len(digest), 64)
            self.assertEqual(digest, sha256_file(self.store.artifact_path(name)))
        self.assertIn("trivy-report.json", entries)

    def test_inventory_round_trip_is_per_service_and_version(self):
        self.assertFalse(self.store.has_inventory("OVAC-Backend", "8.8.0"))
        self.store.record_inventory("OVAC-Backend", "8.8.0", {"sbom_sha256": "a" * 64, "components": 3})
        self.assertTrue(self.store.has_inventory("OVAC-Backend", "8.8.0"))
        self.assertFalse(self.store.has_inventory("OVAC-Backend", "8.9.0"))
        self.assertEqual(self.store.inventory_record("OVAC-Backend", "8.8.0")["components"], 3)

    def test_ledger_supports_idempotent_publication(self):
        self.assertIsNone(self.store.ledger_get("dt:svc:8.9.0:abc"))
        self.store.ledger_put("dt:svc:8.9.0:abc", {"status": "SUCCESS", "external_id": "p1"})
        self.assertEqual(self.store.ledger_get("dt:svc:8.9.0:abc")["external_id"], "p1")

    def test_pending_queue_is_durable_and_removable(self):
        self.store.enqueue_pending({"artifacts": ["sbom.cdx.json"], "reason": "barad_dur_unreachable"})
        entries = self.store.pending_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["run_id"], "local-20260101T000000Z-abcdef")
        self.assertTrue(self.store.drop_pending())
        self.assertEqual(self.store.pending_entries(), [])

    def test_other_pending_runs_are_not_dropped(self):
        other = RunStore(self.config, "local-20260102T000000Z-aaaaaa").prepare()
        other.enqueue_pending({"reason": "x"})
        self.assertFalse(self.store.drop_pending())
        self.assertEqual(len(self.store.pending_entries()), 1)

    def test_run_ids_are_unique_and_ordered(self):
        first = generate_run_id("local")
        second = generate_run_id("local")
        self.assertNotEqual(first, second)
        self.assertTrue(first.startswith("local-"))
        self.assertEqual(len(first.split("-")), 3)


if __name__ == "__main__":
    unittest.main()

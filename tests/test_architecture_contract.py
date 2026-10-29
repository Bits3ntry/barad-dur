"""Public package and GitHub Action boundaries for the consolidated layout."""
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ArchitectureContractTests(unittest.TestCase):
    def test_reusable_adapters_have_stable_and_compatible_imports(self):
        from integrations.dependency_track import synchronize as public_dt
        from integrations.defectdojo import synchronize as public_dojo
        from barad.integrations.dependency_track import synchronize as legacy_dt
        from barad.integrations.defectdojo import synchronize as legacy_dojo

        self.assertIs(public_dt, legacy_dt)
        self.assertIs(public_dojo, legacy_dojo)

    def test_action_invokes_only_the_installable_cli_surface(self):
        action = (ROOT / "action" / "action.yml").read_text(encoding="utf-8")

        self.assertIn("using: composite", action)
        self.assertIn("barad scan", action)
        self.assertIn("barad run", action)
        self.assertIn("barad health", action)
        self.assertNotIn("barad_security", action)

    def test_cli_configuration_has_only_the_two_supported_remote_adapters(self):
        from barad.config import INTEGRATIONS

        self.assertEqual(INTEGRATIONS, ("dependency_track", "defectdojo"))

    def test_legacy_evidence_store_is_not_shipped_alongside_cli_evidence(self):
        import barad_security.evidence as evidence

        self.assertFalse(hasattr(evidence, "RunStore"))

    def test_runtime_contract_tests_are_root_level_not_part_of_cli_package(self):
        self.assertTrue((ROOT / "tests" / "test_scan_contract.py").is_file())
        self.assertFalse((ROOT / "cli" / "tests").exists())


if __name__ == "__main__":
    unittest.main()

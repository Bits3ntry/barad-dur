"""Public package and GitHub Action boundaries for the consolidated layout."""
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ArchitectureContractTests(unittest.TestCase):
    def test_reusable_adapters_expose_their_direct_public_imports(self):
        from integrations.dependency_track import synchronize as dependency_track
        from integrations.defectdojo import synchronize as defectdojo

        self.assertTrue(callable(dependency_track))
        self.assertTrue(callable(defectdojo))

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

    def test_cli_core_has_one_evidence_implementation(self):
        import barad.core.evidence as evidence

        self.assertFalse(hasattr(evidence, "RunStore"))

    def test_runtime_contract_tests_are_root_level_not_part_of_cli_package(self):
        self.assertTrue((ROOT / "tests" / "test_scan_contract.py").is_file())
        self.assertFalse((ROOT / "cli" / "tests").exists())

    def test_active_packages_are_limited_to_cli_and_integrations(self):
        from barad.core import TrivyRunner
        from integrations import dependency_track, defectdojo

        self.assertTrue(callable(TrivyRunner))
        self.assertTrue(callable(dependency_track.synchronize))
        self.assertTrue(callable(defectdojo.synchronize))
        self.assertFalse((ROOT / "barad_security").is_dir())
        self.assertFalse((ROOT / "cli" / "barad" / "integrations").is_dir())


if __name__ == "__main__":
    unittest.main()

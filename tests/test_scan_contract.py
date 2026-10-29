import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from cli_support import CliTestCase, FakeTrivy, invoke


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class ScanContractTests(CliTestCase):
    def test_scan_without_git_writes_json_cyclonedx_and_manifest(self):
        self.write("pyproject.toml", '[project]\nname = "demo"\nversion = "1.2.3"\n')

        code, out, err, manifest, run_dir = self.scan(cwd=self.root)

        self.assertEqual(code, 0, err)
        self.assertEqual(err, "")
        self.assertIn(f"scan {self.root.name}: completed", out)
        self.assertEqual(manifest["status"], "completed")
        self.assertEqual(manifest["scan"]["status"], "SUCCESS")
        self.assertEqual(manifest["project"]["name"], self.root.name)
        self.assertEqual(manifest["project"]["name_source"], "directory")
        self.assertEqual(manifest["project"]["target"], {"type": "fs", "value": "."})
        self.assertEqual(manifest["application_version"]["value"], "1.2.3")
        self.assertEqual(manifest["application_version"]["source"], "pyproject")
        self.assertIsNone(manifest["commit"])
        self.assertFalse(manifest["git"]["available"])
        self.assertEqual(manifest["scan"]["scanner_versions"]["trivy"], "0.76.1")
        self.assertTrue(manifest["scan"]["started_at"])
        self.assertTrue(manifest["scan"]["finished_at"])
        self.assertEqual(manifest["inventory"]["comparison"], "no_previous")
        self.assertIsNone(manifest["inventory"]["previous"])
        self.assertEqual(run_dir.parent, self.default_output.resolve())
        self.assertEqual(run_dir.name, manifest["run"]["id"])
        self.assertEqual(
            manifest["run"]["directory"], f".barad/reports/{manifest['run']['id']}"
        )

        report = run_dir / "security.json"
        sbom = run_dir / "sbom.cdx.json"
        self.assertTrue(report.is_file())
        self.assertTrue(sbom.is_file())
        self.assertTrue((run_dir / "manifest.json").is_file())
        self.assertTrue((run_dir / "security.sanitized.json").is_file())
        self.assertTrue(self.state_path.is_file())
        self.assertEqual(manifest["artifacts"]["security.json"]["sha256"], digest(report))
        self.assertEqual(manifest["artifacts"]["sbom.cdx.json"]["sha256"], digest(sbom))
        self.assertEqual(
            manifest["artifacts"]["security.json"]["sensitivity"], "local_only"
        )
        self.assertNotIn("do-not-publish", (run_dir / "security.sanitized.json").read_text())
        self.assertEqual(len(manifest["inventory"]["fingerprint"]), 64)
        self.assertEqual(FakeTrivy.instances[-1].scan_type, "fs")
        self.assertEqual(manifest["state"]["directory"], ".barad/state")
        self.assertEqual(manifest["inventory"]["target"], {"type": "fs", "value": "."})
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertNotIn("publication", json.dumps(state))
        self.assertNotIn("published", json.dumps(state))

    def test_missing_scan_path_is_rejected_with_exact_message(self):
        missing = self.root / "missing"

        code, out, err = invoke(["scan", str(missing)], cwd=self.root)

        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err, f"error: scan path not found: {missing.resolve()}\n")

    def test_dockerfile_is_not_claimed_as_an_image_target(self):
        dockerfile = self.write("Dockerfile", "FROM scratch\n")

        code, out, err = invoke(["scan", str(dockerfile)], cwd=self.root)

        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(
            err,
            f"error: scan path is not a directory: {dockerfile.resolve()}; a Dockerfile is a build "
            "definition, not an image target (configure scan.target_type: image with a built "
            "image reference)\n",
        )

    def test_jar_file_is_an_explicit_filesystem_target(self):
        jar = self.write('libs/app.jar', 'placeholder jar bytes')
        code, out, err, manifest, run_dir = self.scan(str(jar), cwd=self.root)
        self.assertEqual((code, err), (0, ''))
        self.assertEqual(manifest['project']['target'], {'type': 'fs', 'value': 'app.jar'})
        self.assertEqual(FakeTrivy.instances[-1].scan_target(), 'app.jar')
        self.assertEqual(run_dir.parent, (jar.parent / '.barad/reports').resolve())

    def test_configured_jar_target_uses_its_project_root(self):
        self.write('libs/app.jar', 'placeholder jar bytes')
        self.write_config('version: 1\nscan:\n  target: libs/app.jar\n')
        code, out, err, manifest, run_dir = self.scan(cwd=self.root)
        self.assertEqual((code, err), (0, ''))
        self.assertEqual(manifest['project']['target'], {'type': 'fs', 'value': 'libs/app.jar'})
        self.assertEqual(run_dir.parent, self.default_output.resolve())

    def test_failed_scan_keeps_artifacts_and_exits_nonzero(self):
        FakeTrivy.fail_scan = True

        code, out, err, manifest, run_dir = self.scan(cwd=self.root)

        self.assertEqual(code, 1)
        self.assertEqual(manifest["status"], "failed")
        self.assertEqual(manifest["scan"]["status"], "FAILED")
        self.assertTrue((run_dir / "security.json").is_file())
        self.assertTrue((run_dir / "sbom.cdx.json").is_file())
        self.assertIn("security.json", manifest["artifacts"])
        self.assertIn("error: scan failed: Trivy exited with 1", err)
        self.assertFalse(self.state_path.exists())

    def test_scanner_preflight_failure_still_leaves_a_manifest(self):
        from barad_security.errors import ScannerError

        FakeTrivy.preflight_error = ScannerError("trivy unavailable")

        code, out, err, manifest, run_dir = self.scan(cwd=self.root)

        self.assertEqual(code, 1)
        self.assertEqual(manifest["status"], "failed")
        self.assertEqual(err, "error: trivy unavailable\n")
        self.assertTrue((run_dir / "manifest.json").is_file())

    def test_incomplete_inventory_is_never_reported_as_success(self):
        FakeTrivy.sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5"}

        code, out, err, manifest, run_dir = self.scan(cwd=self.root)

        self.assertEqual(code, 1)
        self.assertEqual(manifest["status"], "incomplete")
        self.assertEqual(manifest["scan"]["status"], "INCOMPLETE")
        self.assertTrue((run_dir / "security.json").is_file())
        self.assertTrue((run_dir / "sbom.cdx.json").is_file())
        self.assertIn("inventory incomplete", err)

    def test_output_outside_the_scan_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as outside:
            code, out, err = invoke(
                ["scan", str(self.root), "--output", outside], cwd=self.root
            )

        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(
            err, f"error: output must stay inside the scan root: {Path(outside).resolve()}\n"
        )

    def test_rejected_output_does_not_touch_state_reports_or_scanner(self):
        code, out, err, manifest, run_dir = self.scan(cwd=self.root)
        self.assertEqual(code, 0, err)
        state_before = self.state_path.read_bytes()
        counters_before = (FakeTrivy.scan_calls, FakeTrivy.sbom_calls,
                           len(FakeTrivy.instances))
        reports_before = sorted(self.default_output.iterdir())

        with tempfile.TemporaryDirectory() as outside:
            code, out, err, manifest, run_dir = self.scan(
                str(self.root), "--output", outside, cwd=self.root
            )

        self.assertEqual(code, 2)
        self.assertEqual(
            err, f"error: output must stay inside the scan root: {Path(outside).resolve()}\n"
        )
        self.assertEqual(self.state_path.read_bytes(), state_before)
        self.assertEqual(
            (FakeTrivy.scan_calls, FakeTrivy.sbom_calls, len(FakeTrivy.instances)),
            counters_before,
        )
        self.assertEqual(sorted(self.default_output.iterdir()), reports_before)

    def test_rejected_configuration_leaves_state_reports_and_counters_untouched(self):
        code, out, err, manifest, run_dir = self.scan(cwd=self.root)
        self.assertEqual(code, 0, err)
        state_before = self.state_path.read_bytes()
        counters_before = (FakeTrivy.scan_calls, FakeTrivy.sbom_calls,
                           len(FakeTrivy.instances))
        reports_before = sorted(self.default_output.iterdir())

        self.write_config("version: 1\nscan:\n  danger: true\n")
        code, out, err, manifest, run_dir = self.scan(cwd=self.root)

        self.assertEqual(code, 2)
        self.assertEqual(err, "error: unknown configuration key: scan.danger\n")
        self.assertEqual(self.state_path.read_bytes(), state_before)
        self.assertEqual(
            (FakeTrivy.scan_calls, FakeTrivy.sbom_calls, len(FakeTrivy.instances)),
            counters_before,
        )
        self.assertEqual(sorted(self.default_output.iterdir()), reports_before)

    def test_scan_accepts_an_absolute_repository_path(self):
        from cli_support import REPO_ROOT

        self.write("marker.txt", "demo\n")

        code, out, err, manifest, run_dir = self.scan(str(self.root), cwd=REPO_ROOT)

        self.assertEqual(code, 0, err)
        self.assertEqual(manifest["project"]["target"], {"type": "fs", "value": "."})
        self.assertEqual(run_dir.parent, self.default_output.resolve())

    def test_both_reports_run_even_when_the_inventory_is_unchanged(self):
        self.scan(cwd=self.root)
        code, out, err, manifest, run_dir = self.scan(cwd=self.root)

        self.assertEqual(code, 0, err)
        self.assertEqual(manifest["inventory"]["comparison"], "unchanged")
        self.assertEqual(FakeTrivy.scan_calls, 2)
        self.assertEqual(FakeTrivy.sbom_calls, 2)

    def test_json_flag_prints_only_the_manifest(self):
        code, out, err, manifest, run_dir = self.scan("--json", cwd=self.root)

        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertTrue(out.startswith("{"))
        self.assertEqual(manifest["run"]["id"], json.loads(out)["run"]["id"])
        self.assertEqual(manifest["schema_version"], "1.0")


if __name__ == "__main__":
    unittest.main()

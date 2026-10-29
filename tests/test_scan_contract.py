import hashlib
import json
import re
import tempfile
import unittest
from pathlib import Path

from cli_support import CliTestCase, FakeTrivy, invoke


def slug(value):
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "")).strip("-.")
    return cleaned[:120] or "unresolved"


def evidence_parent(manifest, reports_root):
    """Reports root plus the project/version folder the CLI writes into."""
    return (Path(reports_root) / slug(manifest["project"]["name"])
            / slug(manifest["application_version"].get("value")))


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
        self.assertEqual(run_dir.parent, evidence_parent(manifest, self.default_output).resolve())
        self.assertEqual(run_dir.name, manifest["run"]["id"])
        self.assertEqual(
            manifest["run"]["directory"],
            f".barad/reports/{slug(manifest['project']['name'])}"
            f"/{slug(manifest['application_version'].get('value'))}/{manifest['run']['id']}",
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
        self.assertEqual(run_dir.parent, evidence_parent(manifest, self.default_output).resolve())

    def test_configured_jar_target_uses_its_project_root(self):
        self.write('libs/app.jar', 'placeholder jar bytes')
        self.write_config('version: 1\nscan:\n  target: libs/app.jar\n')
        code, out, err, manifest, run_dir = self.scan(cwd=self.root)
        self.assertEqual((code, err), (0, ''))
        self.assertEqual(manifest['project']['target'], {'type': 'fs', 'value': 'libs/app.jar'})
        self.assertEqual(run_dir.parent, evidence_parent(manifest, self.default_output).resolve())

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
        from barad.core.errors import ScannerError

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

    def test_output_outside_the_scan_root_is_supported(self):
        with tempfile.TemporaryDirectory() as outside:
            code, out, err, manifest, run_dir = self.scan(
                "--output", outside, cwd=self.root
            )

            self.assertEqual(code, 0, err)
            self.assertEqual(run_dir.parent, evidence_parent(manifest, Path(outside)).resolve())

    def test_rejected_out_does_not_touch_state_reports_or_scanner(self):
        code, out, err, manifest, run_dir = self.scan(cwd=self.root)
        self.assertEqual(code, 0, err)
        state_before = self.state_path.read_bytes()
        counters_before = (FakeTrivy.scan_calls, FakeTrivy.sbom_calls,
                           len(FakeTrivy.instances))
        reports_before = sorted(self.default_output.iterdir())

        code, out, err, manifest, run_dir = self.scan(
            "--out", ".barad/state", cwd=self.root
        )

        self.assertEqual(code, 2)
        self.assertIn("output must not overlap the state directory", err)
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
        self.write("marker.txt", "demo\n")

        with tempfile.TemporaryDirectory() as workspace:
            code, out, err, manifest, run_dir = self.scan(str(self.root), cwd=Path(workspace))

        self.assertEqual(code, 0, err)
        self.assertEqual(manifest["project"]["target"], {"type": "fs", "value": "."})
        self.assertEqual(run_dir.parent, evidence_parent(manifest, Path(workspace) / ".barad" / "reports").resolve())
        self.assertFalse((self.root / ".barad").exists())

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


class ExternalWorkspaceTests(CliTestCase):
    """Scanning another project must not write inside its tree."""

    def test_external_scan_writes_evidence_in_the_invocation_directory(self):
        target = self.root / "external"
        target.mkdir()
        (target / "pyproject.toml").write_text(
            '[project]\nname = "external"\nversion = "3.0.0"\n', encoding="utf-8"
        )
        workspace = self.root / "workspace"
        workspace.mkdir()

        code, out, err, manifest, run_dir = self.scan(str(target), cwd=workspace)

        self.assertEqual(code, 0, err)
        self.assertEqual(manifest["project"]["name"], "external")
        self.assertEqual(run_dir.parent, evidence_parent(manifest, workspace / ".barad" / "reports").resolve())
        self.assertTrue((workspace / ".barad" / "state" / "local-inventory.json").is_file())
        self.assertFalse((target / ".barad").exists())
        self.assertFalse((target / ".barad-dur").exists())
        from barad.core.trivy import TrivyRunner
        cache = FakeTrivy.instances[-1].config.data["trivy"]["cache_dir"]
        self.assertEqual(Path(cache).resolve(),
                         (workspace / ".barad-dur" / "cache" / "trivy").resolve())

    def test_out_option_chooses_the_evidence_directory(self):
        code, out, err, manifest, run_dir = self.scan("--out", str(self.root / "evidence"), cwd=self.root)

        self.assertEqual(code, 0, err)
        self.assertEqual(run_dir.parent, evidence_parent(manifest, self.root / "evidence").resolve())
        self.assertFalse(self.default_output.exists())

    def test_out_short_flag_chooses_the_evidence_directory(self):
        code, out, err, manifest, run_dir = self.scan("-O", "reports", cwd=self.root)

        self.assertEqual(code, 0, err)
        self.assertEqual(run_dir.parent, evidence_parent(manifest, self.root / "reports").resolve())
        self.assertFalse(self.default_output.exists())


class EvidenceCollisionTests(CliTestCase):
    """Same project+version either asks to replace or creates version_(n)."""

    def _scan(self, cwd=None):
        code, out, err, manifest, run_dir = self.scan(cwd=cwd or self.root)
        self.assertEqual(code, 0, err)
        return manifest, run_dir

    def test_repeat_scan_without_a_terminal_creates_version_suffix(self):
        from unittest import mock

        manifest, first_dir = self._scan()
        first_marker = first_dir / "manifest.json"

        with mock.patch("builtins.input", side_effect=AssertionError("must not prompt")):
            second, second_dir = self._scan()

        self.assertNotEqual(first_dir, second_dir)
        self.assertTrue((second_dir.parent.name.endswith("_(1)")))
        self.assertTrue(first_marker.is_file())
        self.assertTrue((second_dir / "manifest.json").is_file())
        self.assertEqual(second_dir.parent.parent,
                         evidence_parent(second, self.default_output).resolve().parent)
        self.assertEqual(first_dir.parent.parent,
                         evidence_parent(manifest, self.default_output).resolve().parent)

    def test_interactive_replace_clears_the_existing_version_folder(self):
        from unittest import mock

        manifest, first_dir = self._scan()
        stale = first_dir / "keep-me-out.json"
        stale.write_text("{}\n", encoding="utf-8")

        with mock.patch("builtins.input", return_value="r"), mock.patch(
            "sys.stdin.isatty", return_value=True
        ):
            second, second_dir = self._scan()

        self.assertEqual(first_dir.parent, second_dir.parent)
        self.assertFalse(stale.exists())
        self.assertTrue((second_dir / "manifest.json").is_file())
        self.assertEqual(len(list(first_dir.parent.iterdir())), 1)

    def test_interactive_non_replace_answer_creates_a_suffixed_folder(self):
        from unittest import mock

        manifest, first_dir = self._scan()

        with mock.patch("builtins.input", return_value="n"), mock.patch(
            "sys.stdin.isatty", return_value=True
        ):
            second, second_dir = self._scan()

        self.assertNotEqual(first_dir, second_dir)
        self.assertTrue((second_dir.parent.name.endswith("_(1)")))
        self.assertTrue((first_dir / "manifest.json").is_file())
        self.assertEqual(first_dir.parent.parent,
                         evidence_parent(manifest, self.default_output).resolve().parent)

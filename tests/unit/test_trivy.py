"""Trivy executor contract: always a JSON report, findings never fail the run."""
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from barad_security.config import build_config
from barad_security.errors import ScannerError
from barad_security.logs import null_logger
from barad_security.trivy import TrivyRunner, count_findings
from tests.support import install_fake_trivy


class TrivyRunnerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "package.json").write_text('{"name":"demo","version":"1.0.0"}', encoding="utf-8")
        self.trivy = install_fake_trivy(self.root / "bin")
        self.log = self.root / "trivy.log"
        self.out = self.root / "out"
        self.out.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def config(self, **trivy):
        settings = {"runner": "local", "executable": str(self.trivy),
                    "cache_dir": ".barad-dur/cache", "timeout_seconds": 60}
        settings.update(trivy)
        return build_config(
            {"version": 1,
             "project": {"name": "OVAC", "service": "OVAC-Backend", "ecosystem": "node"},
             "trivy": settings},
            repo_root=self.repo, environ={})

    def runner(self, **trivy):
        return TrivyRunner(self.config(**trivy), null_logger("test"))

    def test_successful_scan_records_report_and_counts(self):
        outcome = self.runner().scan_json(self.out / "trivy-report.json")
        self.assertEqual(outcome.status, "success")
        self.assertEqual(outcome.exit_code, 0)
        self.assertEqual(outcome.counts["high"], 1)
        self.assertEqual(outcome.counts["low"], 1)
        self.assertEqual(outcome.counts["total"], 2)
        self.assertEqual(outcome.counts["secrets"], 1)
        self.assertEqual(outcome.counts["misconfigurations"], 1)
        self.assertEqual(outcome.version, "0.76.1")
        self.assertTrue((self.out / "trivy-report.json").is_file())
        self.assertIn("--exit-code", outcome.command)
        self.assertEqual(outcome.command[outcome.command.index("--exit-code") + 1], "0")

    def test_argv_is_allowlisted_and_relative(self):
        with mock.patch.dict("os.environ", {"FAKE_TRIVY_LOG": str(self.log)}):
            outcome = self.runner().scan_json(self.out / "trivy-report.json")
        argv = outcome.command
        self.assertEqual(argv[0], str(self.trivy))
        self.assertIn("fs", argv)
        self.assertIn("vuln,secret,misconfig", argv)
        self.assertIn("UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", argv)
        self.assertNotIn(str(self.repo), " ".join(argv))
        self.assertEqual(len(self.log.read_text().splitlines()), 1)

    def test_technical_failure_is_reported_not_raised(self):
        with mock.patch.dict("os.environ", {"FAKE_TRIVY_MODE": "fail"}):
            outcome = self.runner().scan_json(self.out / "trivy-report.json")
        self.assertEqual(outcome.status, "failed")
        self.assertEqual(outcome.exit_code, 1)
        self.assertEqual(outcome.error["code"], "trivy_nonzero_exit")
        self.assertIn("vulnerability database", outcome.error["stderr_tail"])
        self.assertFalse((self.out / "trivy-report.json").exists())

    def test_zero_results_is_not_reported_as_a_clean_scan(self):
        with mock.patch.dict("os.environ", {"FAKE_TRIVY_MODE": "empty-json"}):
            outcome = self.runner().scan_json(self.out / "trivy-report.json")
        self.assertEqual(outcome.status, "success")
        self.assertEqual(outcome.counts["total"], 0)
        self.assertIn("trivy_reported_no_targets", outcome.warnings)

    def test_missing_executable_fails_before_scanning(self):
        runner = self.runner(executable=str(self.root / "does-not-exist"))
        with self.assertRaises(ScannerError) as caught:
            runner.preflight()
        self.assertIn("not found", str(caught.exception))

    def test_sbom_generation_never_enables_security_scanners(self):
        outcome = self.runner().generate_sbom(self.out / "sbom.cdx.json")
        self.assertEqual(outcome.status, "success")
        self.assertIn("cyclonedx", outcome.command)
        self.assertNotIn("--scanners", outcome.command)
        self.assertEqual(outcome.parameters["scanners"], "none (CycloneDX inventory only)")

    def test_docker_mode_separates_read_only_target_from_writable_evidence(self):
        config = build_config(
            {"version": 1, "project": {"name": "OVAC", "service": "svc", "ecosystem": "node"},
             "trivy": {"runner": "docker", "image": "aquasec/trivy:0.76.1"}},
            repo_root=self.repo, environ={})
        runner = TrivyRunner(config, null_logger("test"))
        with mock.patch("shutil.which", return_value="/usr/local/bin/docker"):
            argv, _cwd, mount_target = runner._docker_command(
                format_name="json", output_path=self.out / "report.json", include_scanners=True)
        joined = " ".join(argv)
        self.assertIn(f"{self.repo}:/scan:ro", joined)
        self.assertIn("/out/report.json", joined)
        self.assertNotIn(":/out:ro", joined)
        self.assertEqual(mount_target, self.repo.resolve())
        # Docker options precede the image; every Trivy flag must come after it,
        # otherwise docker itself rejects them ("unknown flag: --format").
        image_index = argv.index("aquasec/trivy:0.76.1")
        self.assertGreater(image_index, 0)
        # The cache is a volume mount in docker mode, not a --cache-dir flag.
        for flag in ("--format", "--output", "--exit-code", "--scanners"):
            self.assertGreater(argv.index(flag), image_index, flag)
        self.assertEqual(argv[image_index + 1], "fs")
        self.assertFalse([argument for argument in argv[:image_index]
                          if argument.startswith("--format")])

    def test_timeout_is_a_technical_failure(self):
        runner = self.runner()
        runner.timeout = 0
        with mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired("trivy", 1)):
            with self.assertRaises(ScannerError) as caught:
                runner.scan_json(self.out / "report.json")
        self.assertIn("budget", str(caught.exception))


class CountTests(unittest.TestCase):
    def test_counts_by_severity_type(self):
        document = {"Results": [
            {"Vulnerabilities": [{"Severity": "CRITICAL"}, {"Severity": "HIGH"}, {"Severity": "HIGH"}]},
            {"Secrets": [{"RuleID": "a"}, {"RuleID": "b"}]},
            {"Misconfigurations": [{"Status": "FAIL"}, {"Status": "PASS"}]},
        ]}
        counts = count_findings(document)
        self.assertEqual(counts["critical"], 1)
        self.assertEqual(counts["high"], 2)
        self.assertEqual(counts["total"], 3)
        self.assertEqual(counts["secrets"], 2)
        self.assertEqual(counts["misconfigurations"], 1)
        self.assertEqual(counts["results"], 3)


if __name__ == "__main__":
    unittest.main()

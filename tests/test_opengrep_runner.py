"""OpenGrep runner contract: a resolved pinned engine, not a preinstalled binary.

The runner must never look for `opengrep` on PATH.  It asks the EngineManager for
the absolute path of the pinned release, which is what makes "install the Barad
CLI and you have everything" true.
"""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cli_support import FakeEngineManager

from barad.core.engines import EngineError
from barad.core.errors import ScannerError
from barad.core.opengrep import OpenGrepRunner


class Config:
    def __init__(self, root):
        self.repo_root = Path(root)
        self.environ = {}
        self.values = {
            "opengrep.rules": "rules.yml",
            "opengrep.timeout_seconds": 60,
            "opengrep.exclude_paths": ["vendor"],
        }

    def get(self, key, default=None):
        return self.values.get(key, default)

    def path(self, value):
        return self.repo_root / value


class UnresolvableEngine:
    def resolve(self, name="opengrep"):
        raise EngineError("Barad pins opengrep 1.33.1 only for linux-aarch64, linux-x86_64")

    def engine(self, name="opengrep"):
        raise EngineError("Barad pins opengrep 1.33.1 only for linux-aarch64, linux-x86_64")


class OpenGrepRunnerTests(unittest.TestCase):
    def test_scan_writes_and_counts_a_json_report_from_versioned_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "rules.yml").write_text("rules: []\n", encoding="utf-8")
            output = root / "evidence" / "sast.json"
            engines = FakeEngineManager()
            runner = OpenGrepRunner(Config(root), None, repo_root=root, engines=engines)
            report = {
                "version": "1.33.1",
                "results": [
                    {"check_id": "rule.error", "extra": {"severity": "ERROR"}},
                    {"check_id": "rule.warning", "extra": {"severity": "WARNING"}},
                ],
                "errors": [],
            }
            commands = []

            def run(argv, **_kwargs):
                commands.append(list(argv))
                if argv[1:] == ["--version"]:
                    return subprocess.CompletedProcess(argv, 0, stdout="OpenGrep 1.33.1\n", stderr="")
                output.write_text(json.dumps(report), encoding="utf-8")
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

            with mock.patch("barad.core.opengrep.subprocess.run", side_effect=run):
                runner.preflight()
                outcome = runner.scan_json(output)

        self.assertTrue(outcome.successful)
        self.assertEqual(outcome.version, "1.33.1")
        self.assertEqual(outcome.counts, {"total": 2, "error": 1, "warning": 1, "info": 0})
        self.assertIn("--config", outcome.command)
        self.assertIn("rules.yml", outcome.parameters["rules"])
        self.assertEqual(outcome.parameters["exit_code_policy"], "findings do not fail the run")

    def test_the_managed_engine_absolute_path_is_the_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "rules.yml").write_text("rules: []\n", encoding="utf-8")
            engines = FakeEngineManager()
            runner = OpenGrepRunner(Config(root), None, repo_root=root, engines=engines)

            runner.preflight()

            self.assertEqual(runner.executable(), engines.path.resolve())
            self.assertTrue(runner.executable().is_absolute())
            self.assertNotEqual(runner.executable().name, "opengrep-lookup")

    def test_preflight_never_requires_a_preinstalled_opengrep_on_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "rules.yml").write_text("rules: []\n", encoding="utf-8")
            engines = FakeEngineManager()
            runner = OpenGrepRunner(Config(root), None, repo_root=root, engines=engines)
            empty_path = {"PATH": ""}

            with mock.patch.dict(os.environ, empty_path, clear=False):
                runner.preflight()

            self.assertEqual(FakeEngineManager.resolve_calls, 1)

    def test_scan_records_the_pinned_engine_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "rules.yml").write_text("rules: []\n", encoding="utf-8")
            output = root / "evidence" / "sast.json"
            engines = FakeEngineManager()
            runner = OpenGrepRunner(Config(root), None, repo_root=root, engines=engines)

            def run(argv, **_kwargs):
                if argv[1:] == ["--version"]:
                    return subprocess.CompletedProcess(argv, 0, stdout="OpenGrep 1.33.1\n", stderr="")
                output.write_text(json.dumps({"version": "1.33.1", "results": [],
                                              "errors": []}), encoding="utf-8")
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

            with mock.patch("barad.core.opengrep.subprocess.run", side_effect=run):
                runner.preflight()
                outcome = runner.scan_json(output)

        engine = outcome.parameters["engine"]
        self.assertEqual(engine["name"], "opengrep")
        self.assertEqual(engine["version"], "1.33.1")
        self.assertEqual(engine["platform"], "linux-x86_64")
        self.assertEqual(engine["sha256"], FakeEngineManager.spec["sha256"])
        self.assertEqual(len(engine["sha256"]), 64)

    def test_preflight_reports_an_unresolvable_engine_as_a_scanner_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "rules.yml").write_text("rules: []\n", encoding="utf-8")
            runner = OpenGrepRunner(Config(root), None, repo_root=root,
                                    engines=UnresolvableEngine())

            with self.assertRaises(ScannerError) as caught:
                runner.preflight()

        self.assertIn("linux-x86_64", caught.exception.message)
        self.assertEqual(caught.exception.kind, "engine_error")


if __name__ == "__main__":
    unittest.main()

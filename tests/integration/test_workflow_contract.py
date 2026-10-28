"""Structural checks for the surfaces that cannot run in this test suite.

The GitHub workflow, the act payload and the Git hooks cannot be executed here
(no `act`, no GitHub runner, hooks are per-clone). What can be proven is that they
stay wired to the single runner, that the secret-free job stays secret-free, and
that the example configuration still validates through the public CLI.
"""
import json
import re
import unittest
from pathlib import Path

import yaml

from tests.support import REPO_ROOT, run_cli

WORKFLOW = REPO_ROOT / ".github" / "workflows" / "security.yml"
HOOK = REPO_ROOT / "examples" / "hooks" / "pre-commit"
HUSKY = REPO_ROOT / "examples" / "hooks" / "husky-pre-commit"
ACT_PAYLOAD = REPO_ROOT / "examples" / "act" / "pull_request.json"
EXAMPLES = ["node", "react", "fastapi"]


class WorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        # PyYAML maps the `on:` key to the boolean True with YAML 1.1 rules.
        cls.triggers = cls.document.get("on") or cls.document.get(True) or {}
        cls.jobs = cls.document["jobs"]

    def steps(self, job):
        return self.jobs[job]["steps"]

    def test_triggers_cover_pr_push_release_dispatch_and_reuse(self):
        self.assertEqual(set(self.triggers), {"workflow_call", "pull_request", "push",
                                              "release", "workflow_dispatch"})
        self.assertIn("config-file", self.triggers["workflow_call"]["inputs"])
        secrets = self.triggers["workflow_call"]["secrets"]
        for name in ("BARAD_DUR_TOKEN", "DTRACK_API_KEY", "DOJO_TOKEN"):
            self.assertIn(name, secrets)

    def test_scan_job_calls_the_single_runner_and_keeps_no_secrets(self):
        scan = self.jobs["scan"]
        self.assertEqual(self.document["permissions"]["contents"], "read")
        text = json.dumps(scan)
        for variable in ("BARAD_DUR_TOKEN", "DTRACK_API_KEY", "DOJO_TOKEN", "secrets."):
            self.assertNotIn(variable, text)
        run_steps = " ".join(step.get("run", "") for step in self.steps("scan"))
        self.assertIn("python -m barad_security run", run_steps)
        self.assertIn('--event "$event"', run_steps)
        self.assertIn("--config \"$BARAD_SECURITY_CONFIG\"", run_steps)
        self.assertNotIn("trivy fs", run_steps)
        self.assertNotIn("cyclonedx", run_steps)

    def test_full_history_is_fetched_for_pull_request_merges(self):
        checkout = self.steps("scan")[0]
        self.assertEqual(checkout["with"]["fetch-depth"], 0)
        self.assertIs(checkout["with"]["persist-credentials"], False)

    def test_evidence_is_uploaded_even_when_the_scan_fails(self):
        upload = [step for step in self.steps("scan") if step.get("uses", "").startswith("actions/upload-artifact")][0]
        self.assertEqual(upload["if"], "always()")
        self.assertIn(".barad-dur/security", upload["with"]["path"])

    def test_publish_job_is_gated_against_forks_and_syncs_without_rescanning(self):
        publish = self.jobs["publish"]
        condition = publish["if"]
        self.assertIn("pull_request", condition)
        self.assertIn("pull_request_target", condition)
        self.assertIn("fork", condition)
        self.assertIn("needs.scan.result", condition)
        run_steps = " ".join(step.get("run", "") for step in self.steps("publish"))
        self.assertIn("python -m barad_security sync --pending", run_steps)
        self.assertNotIn("barad_security run", run_steps)
        environment = json.dumps(publish)
        self.assertIn("secrets.DTRACK_API_KEY", environment)

    def test_publish_downloads_the_preserved_evidence(self):
        download = [step for step in self.steps("publish")
                    if step.get("uses", "").startswith("actions/download-artifact")][0]
        self.assertEqual(download["with"]["path"], ".")

    def test_hooks_reuse_the_runner_instead_of_reimplementing_it(self):
        for path in (HOOK, HUSKY):
            text = path.read_text(encoding="utf-8")
            self.assertIn("barad_security run", text, path.name)
            self.assertNotIn("trivy fs", text, path.name)
            self.assertNotIn("cyclonedx", text, path.name)
            self.assertIn("BARAD_SECURITY_SKIP", text, path.name)

    def test_act_payload_has_the_fields_the_workflow_reads(self):
        payload = json.loads(ACT_PAYLOAD.read_text(encoding="utf-8"))
        self.assertEqual(payload["pull_request"]["number"], 12)
        self.assertIs(payload["pull_request"]["head"]["repo"]["fork"], False)
        self.assertEqual(payload["number"], 12)

    def test_runner_script_is_executable_and_calls_the_module(self):
        script = (REPO_ROOT / "bin" / "barad-security").read_text(encoding="utf-8")
        self.assertIn("-m barad_security", script)
        self.assertTrue((REPO_ROOT / "bin" / "barad-security").stat().st_mode & 0o111)

    def test_example_configurations_validate_through_the_cli(self):
        for example in EXAMPLES:
            with self.subTest(example=example):
                result = run_cli(["validate-config", "--repository", str(REPO_ROOT / "examples" / example)])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("configuration valid", result.stdout)
                self.assertNotIn("error", result.stdout.lower())

    def test_this_repository_scans_itself_with_the_container_engine(self):
        result = run_cli(["validate-config", "--repository", str(REPO_ROOT)])
        self.assertEqual(result.returncode, 0, result.stderr)
        document = yaml.safe_load((REPO_ROOT / "barad-security.yml").read_text(encoding="utf-8"))
        self.assertIn("docker", document["trivy"]["runner"])          # ${BARAD_TRIVY_RUNNER:-docker}
        self.assertEqual(document["trivy"]["image"], "aquasec/trivy:0.76.1")
        for excluded in (".venv", "artifacts", ".git", ".codegraph"):
            self.assertIn(excluded, document["trivy"]["exclude_paths"])

    def test_declared_version_matches_the_package(self):
        import barad_security

        declared = (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip()
        self.assertEqual(declared, barad_security.__version__)

    def test_invalid_configuration_is_rejected_with_exit_code_two(self):
        with __import__("tempfile").TemporaryDirectory() as directory:
            path = Path(directory) / "barad-security.yml"
            path.write_text("version: 1\nproject:\n  name: OVAC\n  service: ''\n", encoding="utf-8")
            result = run_cli(["validate-config", "--repository", directory])
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("invalid configuration", result.stderr)


if __name__ == "__main__":
    unittest.main()

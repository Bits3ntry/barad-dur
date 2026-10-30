"""Contract for the migrated `.github/workflows/security.yml` CI adapter.

GitHub-hosted execution is unavailable in this environment, so the workflow is
verified two ways:

* structurally, by reading the workflow and `config/ci.barad.yml` as data;
* behaviorally, by executing the extracted shell of the scan and publish steps
  against a stub `barad` executable. That proves the credential boundary, the
  visible skip when credentials are absent, and that publication failures are
  never masked.

The workflow must call the installable `barad` CLI only. `barad run` rescans
inside the trusted job; it never resumes the artifacts of the credential-free
scan job, so no job uploads a raw secret-bearing report.
"""
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from cli_support import REPO_ROOT
from barad.config import load_settings, read_project_config

WORKFLOW = REPO_ROOT / ".github" / "workflows" / "security.yml"
CI_CONFIG = REPO_ROOT / "config" / "ci.barad.yml"
DOCS = REPO_ROOT / "docs" / "CLI.md"

PUBLISH_CREDENTIALS = ("DTRACK_URL", "DTRACK_API_KEY")
ALL_CREDENTIAL_NAMES = PUBLISH_CREDENTIALS
LEGACY_REFERENCES = ("barad-security sync", "requirements.txt", "./bin/barad-security")


def workflow_code():
    """Workflow text without comments: comments may document removed names."""
    lines = [line for line in WORKFLOW.read_text(encoding="utf-8").splitlines()
             if not line.lstrip().startswith("#")]
    return "\n".join(lines)


def load_workflow():
    document = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    triggers = document.pop("on", None)
    if triggers is None:
        triggers = document.pop(True, None)
    document["on"] = triggers
    return document


def job_steps(job):
    return job.get("steps") or []


def step_text(step):
    return yaml.safe_dump(step, sort_keys=False)


def steps_with_run(job):
    return [step for step in job_steps(job) if "run" in step]


def missing_credential_names(script):
    return [name for name in PUBLISH_CREDENTIALS if name in script]


class WorkflowStructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = load_workflow()
        cls.jobs = cls.document["jobs"]
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        cls.code = workflow_code()

    def test_workflow_keeps_scan_and_publish_jobs(self):
        self.assertEqual(set(self.jobs), {"scan", "publish"})
        self.assertEqual(self.jobs["publish"]["needs"], "scan")

    def test_triggers_keep_pull_request_push_release_and_reusable_call(self):
        triggers = self.document["on"]
        self.assertIn("workflow_call", triggers)
        self.assertIn("pull_request", triggers)
        self.assertIn("release", triggers)
        self.assertIn("push", triggers)

    def test_scan_job_never_receives_credentials(self):
        scan_text = yaml.safe_dump(self.jobs["scan"], sort_keys=False)
        self.assertNotIn("secrets.", scan_text)
        for name in ALL_CREDENTIAL_NAMES:
            self.assertNotIn(name, scan_text, f"scan job must not reference {name}")

    def test_publish_job_keeps_secrets_inside_run_steps(self):
        publish = self.jobs["publish"]
        self.assertFalse(publish.get("env"), "job-level env would expose secrets to every step")
        for step in job_steps(publish):
            text = step_text(step)
            if "secrets." not in text:
                continue
            self.assertIn("run", step, "secrets are only allowed in a run step")
            self.assertNotIn("uses", step, "a third-party action must not receive secrets")
        credential_steps = [step for step in steps_with_run(publish)
                            if any(name in step_text(step) for name in PUBLISH_CREDENTIALS)]
        self.assertEqual(len(credential_steps), 1, "one publication step carries the secrets")

    def test_publish_job_is_limited_to_trusted_refs(self):
        condition = str(self.jobs["publish"].get("if") or "")
        self.assertIn("needs.scan.result", condition)
        self.assertIn("release", condition)
        self.assertIn("default_branch", condition)
        self.assertNotIn("pull_request.head.repo.fork", condition)
        self.assertNotRegex(condition, r"event_name\s*==\s*'pull_request'")

    def test_publication_failures_are_never_masked(self):
        self.assertNotIn("|| true", self.text)
        self.assertNotIn("||true", self.text)
        publish_run = "\n".join(step["run"] for step in steps_with_run(self.jobs["publish"]))
        self.assertIn("exit \"$status\"", publish_run)

    def test_workflow_runs_the_installable_barad_cli(self):
        for legacy in LEGACY_REFERENCES:
            self.assertNotIn(legacy, self.code, f"obsolete reference remains: {legacy}")
        installs = [step.get("run", "") for job in self.jobs.values()
                    for step in job_steps(job) if "pip install" in step.get("run", "")]
        self.assertTrue(installs)
        for command in installs:
            self.assertIn("pip install", command)
            self.assertRegex(command, r"pip install[^\n]*\s\.")
        self.assertIn("barad scan", self.code)
        self.assertIn("barad run", self.code)

    def test_reusable_workflow_inputs_are_current(self):
        inputs = self.document["on"]["workflow_call"]["inputs"]
        self.assertEqual(set(inputs), {"config-file", "python-version"})
        self.assertEqual(inputs["config-file"]["default"], "config/ci.barad.yml")
        self.assertNotIn("trivy-runner", self.code)
        secrets = self.document["on"]["workflow_call"]["secrets"]
        self.assertEqual(set(secrets), set(PUBLISH_CREDENTIALS))
        self.assertNotIn("DOJO_", self.code)

    def test_workflow_jobs_reference_the_explicit_ci_config(self):
        for job in self.jobs.values():
            for step in steps_with_run(job):
                if "barad " not in step["run"]:
                    continue
                self.assertIn("--config", step["run"])
                self.assertIn('"$BARAD_CONFIG"', step["run"])
                self.assertIn("BARAD_CONFIG", step.get("env") or {})

    def test_positional_target_keeps_the_scan_root_at_the_repository_root(self):
        document, _source = read_project_config(CI_CONFIG)
        self.assertEqual(document["scan"]["target_type"], "fs")
        self.assertNotIn("target", document["scan"])
        commands = [step["run"] for job in self.jobs.values()
                    for step in steps_with_run(job) if "barad " in step["run"]]
        self.assertTrue(commands)
        for command in commands:
            self.assertRegex(command, r"(barad scan|barad run) \. --config",
                             "a bare config under config/ would narrow the scan root to config/")

    def test_ci_invocation_resolves_the_repository_root(self):
        """The workflow command shape, executed by the real resolver."""
        from argparse import Namespace

        from barad.commands.scan import resolve

        previous = Path.cwd()
        os.chdir(REPO_ROOT)
        try:
            settings, target_type, target_value, _context, _name = resolve(
                Namespace(path=".", config="config/ci.barad.yml", output=None))
        finally:
            os.chdir(previous)
        self.assertEqual(settings.root, Path(REPO_ROOT).resolve())
        self.assertEqual((target_type, target_value), ("fs", "."))
        self.assertEqual(settings.document["project"]["name"], "barad-dur")

    def test_each_job_uploads_sanitized_evidence_only(self):
        for name in ("scan", "publish"):
            uploads = [step for step in job_steps(self.jobs[name])
                       if str(step.get("uses", "")).startswith("actions/upload-artifact")]
            self.assertEqual(len(uploads), 1, f"{name} must preserve its own evidence")
            upload = uploads[0]
            self.assertEqual(upload.get("if"), "always()")
            paths = upload["with"]["path"]
            self.assertIn("manifest.json", paths)
            self.assertIn("security.sanitized.json", paths)
            self.assertIn("sbom.cdx.json", paths)
            self.assertNotIn("execution.log", paths)
            for line in paths.splitlines():
                entry = line.strip()
                if not entry:
                    continue
                self.assertNotEqual(Path(entry).name, "security.json",
                                    "the raw report embeds secret matches")
                # `.barad/reports` or `.barad/reports/*` would sweep in security.json.
                self.assertNotEqual(entry.rstrip("/*"), ".barad/reports",
                                    "uploading the reports directory includes the raw report")


class CiConfigTests(unittest.TestCase):
    def setUp(self):
        self.document, self.source = read_project_config(CI_CONFIG)

    def test_config_publishes_only_dependency_track_without_committing_secrets(self):
        integrations = self.document["integrations"]
        self.assertTrue(integrations["dependency_track"]["enabled"])
        self.assertNotIn("defectdojo", integrations)
        self.assertEqual(self.document["scan"]["scanners"], ["secret", "misconfig"])
        text = CI_CONFIG.read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"https?://", text), "endpoints must come from the environment")
        for name in ("token", "api_key", "password", "secret"):
            for block in integrations.values():
                self.assertNotIn(name, block)

    def test_config_validates_without_any_credential_in_the_environment(self):
        settings = load_settings(self.document, source=self.source, root=REPO_ROOT,
                                 project_name="barad-dur", environ={})
        self.assertEqual(settings.document["output"]["directory"], ".barad/reports")
        self.assertFalse(settings.connection("dependency_track")["token_configured"])
        self.assertNotIn("defectdojo", self.document["integrations"])
        self.assertEqual(settings.secret_values(), [])


class StepScriptTests(unittest.TestCase):
    """Execute the extracted step shell against a stub `barad` executable."""

    @classmethod
    def setUpClass(cls):
        document = load_workflow()
        cls.scan_script = next(step["run"] for step in steps_with_run(document["jobs"]["scan"])
                               if "barad scan" in step["run"])
        cls.publish_script = next(step["run"] for step in steps_with_run(document["jobs"]["publish"])
                                  if "barad run" in step["run"])

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.directory = Path(self._tmp.name)
        self.stub_dir = self.directory / "bin"
        self.stub_dir.mkdir()
        self.argv_log = self.directory / "barad.argv"

    def stub(self, exit_code=0):
        stub = self.stub_dir / "barad"
        stub.write_text(
            "#!/bin/sh\n"
            f"printf '%s\\n' \"$@\" > '{self.argv_log}'\n"
            "echo '{\"status\": \"completed\"}'\n"
            f"exit {exit_code}\n",
            encoding="utf-8",
        )
        stub.chmod(0o755)

    def run_step(self, script, extra_env=None, stub_exit=0):
        self.stub(stub_exit)
        environment = {
            "PATH": f"{self.stub_dir}:/usr/bin:/bin:/usr/local/bin",
            "HOME": str(self.directory),
            "BARAD_CONFIG": "config/ci.barad.yml",
        }
        environment.update(extra_env or {})
        completed = subprocess.run(["bash", "-euo", "pipefail", "-c", script],
                                   cwd=self.directory, env=environment,
                                   capture_output=True, text=True, timeout=120)
        return completed

    def credentials(self):
        return {"DTRACK_URL": "https://dtrack.invalid", "DTRACK_API_KEY": "private-dt"}

    def test_scan_step_propagates_a_scan_failure(self):
        completed = self.run_step(self.scan_script, stub_exit=1)
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertTrue(self.argv_log.is_file())
        argv = self.argv_log.read_text(encoding="utf-8").split()
        self.assertEqual(argv[:2], ["scan", "."])
        self.assertIn("--config", argv)

    def test_publish_step_skips_visibly_when_credentials_are_absent(self):
        completed = self.run_step(self.publish_script)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("::notice", completed.stdout)
        self.assertIn("Publication skipped", completed.stdout)
        self.assertIn("no publication was attempted", completed.stdout.lower())
        self.assertFalse(self.argv_log.exists(), "no scan or publication may run without credentials")
        self.assertFalse((self.directory / "publication.json").exists())

    def test_publish_step_skips_visibly_when_a_single_credential_is_missing(self):
        credentials = self.credentials()
        credentials.pop("DTRACK_API_KEY")
        completed = self.run_step(self.publish_script, credentials)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("DTRACK_API_KEY", completed.stdout)
        self.assertFalse(self.argv_log.exists())

    def test_publish_step_rescans_inside_the_trusted_job(self):
        completed = self.run_step(self.publish_script, self.credentials())
        self.assertEqual(completed.returncode, 0, completed.stderr)
        argv = self.argv_log.read_text(encoding="utf-8").split()
        self.assertEqual(argv[:2], ["run", "."])
        self.assertIn("--config", argv)
        self.assertTrue((self.directory / "publication.json").is_file())
        self.assertNotIn("private-dt", completed.stdout)

    def test_publish_step_propagates_a_publication_failure(self):
        completed = self.run_step(self.publish_script, self.credentials(), stub_exit=4)
        self.assertEqual(completed.returncode, 4, completed.stderr)

    def test_publish_step_names_every_missing_credential_it_checks(self):
        names = missing_credential_names(self.publish_script)
        self.assertEqual(names, list(PUBLISH_CREDENTIALS))


class ActionEngineTests(unittest.TestCase):
    def test_composite_action_delegates_opengrep_to_the_cli_engine_manager(self):
        action = (REPO_ROOT / "action" / "action.yml").read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertNotIn("install-opengrep.sh", action)
        self.assertNotIn("Install OpenGrep", action)
        self.assertNotIn("Install pinned OpenGrep", workflow)
        self.assertIn("barad scan", action)
        self.assertFalse((REPO_ROOT / "action" / "install-opengrep.sh").exists())


class DocumentationTests(unittest.TestCase):
    def test_docs_describe_the_migrated_workflow(self):
        text = DOCS.read_text(encoding="utf-8")
        self.assertIn("config/ci.barad.yml", text)
        self.assertIn("barad run", text)
        self.assertIn("action/action.yml", text)
        self.assertIn("OpenGrep", text)
        self.assertNotIn("trivy-runner", text)
        self.assertNotIn("still calls a legacy runner", text)
        self.assertNotIn("A future GitHub Action", text)


if __name__ == "__main__":
    unittest.main()

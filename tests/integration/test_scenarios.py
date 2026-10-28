"""End-to-end CLI scenarios from the acceptance table.

Each test drives the public entry point (`python -m barad_security`) against a
real temporary Git repository, with deterministic Trivy reports from the fake
binary and mock HTTP servers for the external systems. Nothing here depends on a
network service; the one test that uses real Trivy is in `test_trivy_real.py`.
"""
import json
import os
import tempfile
import unittest
from pathlib import Path

import yaml

from tests.support import (
    MockServer, commit_all, init_repo, install_fake_trivy, read_json, run_cli, write_file,
)

NODE_FILES = {
    "package.json": json.dumps({"name": "ovac-backend", "version": "8.8.0"}, indent=2) + "\n",
    "package-lock.json": json.dumps({"name": "ovac-backend", "version": "8.8.0",
                                     "lockfileVersion": 3, "requires": True}, indent=2) + "\n",
    "src/index.ts": "export const health = () => 'ok';\n",
    "Dockerfile": "FROM node:22-alpine\nUSER node\n",
}


def configuration(repo, trivy_executable, **sections):
    document = {
        "version": 1,
        "project": {"name": "OVAC", "service": "OVAC-Backend", "ecosystem": "node", "path": "."},
        "trivy": {"runner": "local", "executable": str(trivy_executable), "scan_type": "fs",
                  "timeout_seconds": 120},
        "artifacts": {"directory": ".barad-dur/security"},
        "integrations": {
            "barad_dur": {"enabled": False},
            "dependency_track": {"enabled": False},
            "defectdojo": {"enabled": False},
        },
    }
    for key, value in sections.items():
        if isinstance(value, dict) and isinstance(document.get(key), dict):
            document[key].update(value)
        else:
            document[key] = value
    path = Path(repo) / "barad-security.yml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


class ScenarioBase(unittest.TestCase):
    """Shared harness: a real Git repository, a deterministic Trivy, a mock platform."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.repo = init_repo(self.root / "repo")
        for relative, content in NODE_FILES.items():
            write_file(self.repo, relative, content)
        self.trivy = install_fake_trivy(self.root / "bin")
        self.config = configuration(self.repo, self.trivy)
        self.first = commit_all(self.repo, "initial")

    def tearDown(self):
        self._tmp.cleanup()

    # -- helpers -----------------------------------------------------------
    def run_cli(self, *args, env=None, expect=0):
        result = run_cli([*args, "--repository", str(self.repo), "--config", str(self.config),
                          "--json"], cwd=self.root, env=env)
        self.assertEqual(result.returncode, expect,
                         f"stdout={result.stdout}\nstderr={result.stderr}")
        return result

    def manifest(self, result):
        return json.loads(result.stdout)

    def run_once(self, *args, env=None, expect=0):
        return self.manifest(self.run_cli("run", *args, env=env, expect=expect))

    def run_dir(self, manifest):
        """Resolve the run directory from its id, never from directory ordering."""
        return self.repo / ".barad-dur" / "security" / "runs" / manifest["run_id"]

class Scenario(ScenarioBase):
    """The acceptance table, one test per row."""

    # -- scenario 1 --------------------------------------------------------
    def test_code_only_change_runs_trivy_and_skips_sbom(self):
        first = self.run_once("--event", "push", "--base-ref", self.first)
        self.assertTrue(first["decisions"]["generate_sbom"])   # initial inventory
        write_file(self.repo, "src/index.ts", "export const health = () => 'still ok';\n")
        commit_all(self.repo, "code only")
        manifest = self.run_once("--event", "push", "--base-ref", "HEAD^")
        self.assertEqual(manifest["steps"]["trivy"]["status"], "SUCCESS")
        self.assertNotIn("sbom", manifest["steps"])
        self.assertFalse(manifest["decisions"]["generate_sbom"])
        self.assertEqual(manifest["decisions"]["sbom_reason"], "no_inventory_change")
        run_dir = self.run_dir(manifest)
        self.assertTrue((run_dir / "trivy-report.json").is_file())
        self.assertFalse((run_dir / "sbom.cdx.json").exists())
        self.assertTrue((run_dir / "decisions.json").is_file())
        self.assertTrue((run_dir / "checksums.sha256").is_file())

    # -- scenario 2 --------------------------------------------------------
    def test_lockfile_change_generates_a_second_report_set(self):
        self.run_once("--event", "push", "--base-ref", self.first)
        write_file(self.repo, "package-lock.json", json.dumps(
            {"name": "ovac-backend", "version": "8.8.0", "lockfileVersion": 3,
             "packages": {"node_modules/axios": {"version": "1.7.0"}}}, indent=2) + "\n")
        head = commit_all(self.repo, "bump axios")
        manifest = self.run_once("--event", "pr", "--base-ref", self.first)
        self.assertTrue(manifest["changes"]["dependency_changed"])
        self.assertEqual(manifest["decisions"]["sbom_reason"], "dependency_changed")
        self.assertEqual(manifest["git"]["commit_sha"], head)
        self.assertEqual(manifest["git"]["base_sha"], self.first)
        self.assertEqual(manifest["steps"]["sbom"]["status"], "SUCCESS")
        run_dir = self.run_dir(manifest)
        self.assertTrue((run_dir / "trivy-report.json").is_file())
        self.assertTrue((run_dir / "sbom.cdx.json").is_file())
        checksums = (run_dir / "checksums.sha256").read_text().splitlines()
        names = {line.split("  ")[1] for line in checksums}
        self.assertEqual(names, {"decisions.json", "publication.json", "sbom.cdx.json",
                                 "trivy-report.json", "trivy-report.sanitized.json",
                                 "execution.log", "manifest.json"})

    # -- scenario 3 --------------------------------------------------------
    def test_python_lockfile_change_generates_sbom(self):
        write_file(self.repo, "pyproject.toml", '[project]\nname = "api"\nversion = "1.0.0"\n')
        write_file(self.repo, "uv.lock", "version = 1\n\n[[package]]\nname = \"fastapi\"\nversion = \"0.115.0\"\n")
        commit_all(self.repo, "python deps")
        write_file(self.repo, "uv.lock", "version = 1\n\n[[package]]\nname = \"fastapi\"\nversion = \"0.116.0\"\n")
        commit_all(self.repo, "bump fastapi")
        manifest = self.run_once("--event", "push", "--base-ref", "HEAD^")
        self.assertTrue(manifest["changes"]["dependency_changed"])
        self.assertTrue(manifest["decisions"]["generate_sbom"])

    # -- scenario 4 --------------------------------------------------------
    def test_version_bump_is_reported_as_a_version_change(self):
        self.run_once("--event", "push", "--base-ref", self.first)
        write_file(self.repo, "package.json", json.dumps({"name": "ovac-backend", "version": "8.9.0"},
                                                        indent=2) + "\n")
        commit_all(self.repo, "release 8.9.0")
        manifest = self.run_once("--event", "push", "--base-ref", "HEAD^")
        self.assertTrue(manifest["changes"]["version_changed"])
        self.assertEqual(manifest["changes"]["previous_version"], "8.8.0")
        self.assertEqual(manifest["changes"]["current_version"], "8.9.0")
        self.assertEqual(manifest["decisions"]["sbom_reason"], "application_version_changed")

    # -- scenario 5 --------------------------------------------------------
    def test_dockerfile_change_is_build_context(self):
        self.run_once("--event", "push", "--base-ref", self.first)
        write_file(self.repo, "Dockerfile", "FROM node:24-alpine\nUSER node\n")
        commit_all(self.repo, "new base image")
        manifest = self.run_once("--event", "push", "--base-ref", "HEAD^")
        self.assertTrue(manifest["changes"]["build_context_changed"])
        self.assertFalse(manifest["changes"]["dependency_changed"])
        self.assertEqual(manifest["decisions"]["sbom_reason"], "build_context_changed")

    # -- scenario 6 --------------------------------------------------------
    def test_release_without_dependency_change_still_produces_an_sbom(self):
        self.run_once("--event", "push", "--base-ref", self.first)
        write_file(self.repo, "src/index.ts", "export const health = () => 'release';\n")
        commit_all(self.repo, "release prep")
        manifest = self.run_once("--event", "release", "--version", "8.9.0", "--base-ref", "HEAD^")
        self.assertEqual(manifest["application_version"], "8.9.0")
        self.assertEqual(manifest["decisions"]["sbom_reason"], "release_event")
        self.assertEqual(manifest["steps"]["sbom"]["status"], "SUCCESS")

    # -- scenario 7 --------------------------------------------------------
    def test_pull_request_never_publishes_to_dependency_track(self):
        with MockServer() as server:
            configuration(self.repo, self.trivy,
                          integrations={"dependency_track": {"enabled": True}})
            write_file(self.repo, "package-lock.json", json.dumps({"lockfileVersion": 3, "x": 1}) + "\n")
            commit_all(self.repo, "lockfile")
            manifest = self.run_once("--event", "pr", "--base-ref", self.first,
                                     env={"DTRACK_URL": server.url, "DTRACK_API_KEY": "dt-key-value"})
        self.assertEqual(manifest["steps"]["dependency_track"]["status"], "SKIPPED")
        self.assertEqual(manifest["steps"]["dependency_track"]["reason"], "pull_request_is_temporary")
        self.assertEqual(server.requests, [])

    # -- scenario 8 --------------------------------------------------------
    def test_main_update_refreshes_the_development_project(self):
        with MockServer() as server:
            server.routes["GET /api/v1/project"] = (200, [{"uuid": "dev-uuid", "name": "OVAC-Backend",
                                                          "version": "main"}], {})
            server.routes["PUT /api/v1/bom"] = (200, {"token": "tok"}, {})
            configuration(self.repo, self.trivy, integrations={"dependency_track": {
                "enabled": True, "update_development_project": True, "development_version": "main"}})
            write_file(self.repo, "package-lock.json", json.dumps({"lockfileVersion": 3, "y": 2}) + "\n")
            commit_all(self.repo, "lockfile")
            manifest = self.run_once("--event", "push", "--base-ref", self.first,
                                     env={"DTRACK_URL": server.url, "DTRACK_API_KEY": "dt-key-value"})
            self.assertEqual(manifest["steps"]["dependency_track"]["status"], "PUBLISHED")
            self.assertEqual(manifest["steps"]["dependency_track"]["detail"]["version"], "main")
            bom = [request for request in server.requests if request.path == "/api/v1/bom"]
            self.assertEqual(len(bom), 1)
            self.assertEqual(json.loads(bom[0].body)["project"], "dev-uuid")

    # -- scenario 9 --------------------------------------------------------
    def test_new_release_creates_the_versioned_project(self):
        with MockServer() as server:
            server.routes["GET /api/v1/project"] = (200, [], {})
            server.routes["PUT /api/v1/project"] = (200, {"uuid": "release-uuid"}, {})
            server.routes["PUT /api/v1/bom"] = (200, {"token": "tok"}, {})
            configuration(self.repo, self.trivy, integrations={"dependency_track": {"enabled": True}})
            manifest = self.run_once("--event", "release", "--version", "8.9.0",
                                     env={"DTRACK_URL": server.url, "DTRACK_API_KEY": "dt-key-value"})
            self.assertEqual(manifest["steps"]["dependency_track"]["status"], "PUBLISHED")
            creation = [request for request in server.requests if request.method == "PUT"
                        and request.path == "/api/v1/project"][0]
            self.assertEqual(json.loads(creation.body)["version"], "8.9.0")
            self.assertEqual(manifest["steps"]["dependency_track"]["external_ids"]["project"],
                             "release-uuid")

    # -- scenario 10 -------------------------------------------------------
    def test_unreachable_barad_dur_keeps_evidence_and_can_be_synced_later(self):
        configuration(self.repo, self.trivy, integrations={"barad_dur": {
            "enabled": True, "endpoint_env": "BARAD_DUR_URL", "token_env": "BARAD_DUR_TOKEN"}})
        manifest = self.run_once("--event", "release", "--version", "8.9.0",
                                 env={"BARAD_DUR_URL": "http://127.0.0.1:9",
                                      "BARAD_DUR_TOKEN": "barad-token-value"})
        # The analysis is complete; only the publication is outstanding.
        self.assertEqual(manifest["result"]["status"], "partial")
        self.assertFalse(manifest["result"]["publication_successful"])
        self.assertEqual(manifest["steps"]["barad_dur"]["status"], "PENDING")
        self.assertEqual(manifest["steps"]["barad_dur"]["reason"], "unreachable")
        run_dir = self.run_dir(manifest)
        self.assertTrue((run_dir / "trivy-report.json").is_file())
        self.assertTrue((self.repo / ".barad-dur" / "security" / "pending"
                         / f"{manifest['run_id']}.json").is_file())

        with MockServer() as server:
            server.routes["POST /api/v1/security-runs"] = (200, {"id": "run-remote-1"}, {})
            server.routes["POST /api/v1/security-runs/run-remote-1/artifacts"] = (200, {"ok": True}, {})
            server.routes["POST /api/v1/security-runs/run-remote-1/complete"] = (200, {"ok": True}, {})
            result = self.run_cli("sync", "--run-id", manifest["run_id"],
                                  env={"BARAD_DUR_URL": server.url,
                                       "BARAD_DUR_TOKEN": "barad-token-value"})
            self.assertTrue(json.loads(result.stdout)[0]["resolved"])
            self.assertEqual(len([request for request in server.requests
                                  if request.path == "/api/v1/security-runs"]), 1)
        self.assertFalse((self.repo / ".barad-dur" / "security" / "pending"
                          / f"{manifest['run_id']}.json").is_file())
        synced = read_json(run_dir / "manifest.json")
        self.assertEqual(synced["steps"]["barad_dur"]["status"], "PUBLISHED")
        self.assertEqual(synced["sync"][-1]["resolved"], True)

    # -- scenario 11 -------------------------------------------------------
    def test_unreachable_defectdojo_records_failure_without_losing_the_report(self):
        configuration(self.repo, self.trivy, integrations={"defectdojo": {
            "enabled": True, "publish_trivy_reports": True}})
        manifest = self.run_once("--event", "push", "--base-ref", self.first,
                                 env={"DOJO_URL": "http://127.0.0.1:9", "DOJO_TOKEN": "dojo-token"})
        self.assertEqual(manifest["steps"]["defectdojo"]["status"], "PENDING")
        self.assertEqual(manifest["result"]["status"], "partial")
        self.assertTrue(manifest["result"]["scan_successful"])
        run_dir = self.run_dir(manifest)
        self.assertTrue((run_dir / "trivy-report.json").is_file())
        self.assertTrue((run_dir / "publication.json").is_file())

    # -- scenario 12 -------------------------------------------------------
    def test_trivy_technical_error_fails_the_run_and_saves_the_error(self):
        manifest = self.run_once("--event", "push", "--base-ref", self.first, expect=1,
                                 env={"FAKE_TRIVY_MODE": "fail"})
        self.assertEqual(manifest["result"]["status"], "failed")
        self.assertFalse(manifest["result"]["scan_successful"])
        self.assertEqual(manifest["steps"]["trivy"]["status"], "FAILED")
        self.assertIn("vulnerability database", manifest["steps"]["trivy"]["error"]["stderr_tail"])
        self.assertNotIn("sbom", manifest["steps"])

    # -- scenario 13 -------------------------------------------------------
    def test_vulnerabilities_do_not_fail_the_run(self):
        manifest = self.run_once("--event", "push", "--base-ref", self.first)
        counts = manifest["security"]["counts"]
        self.assertEqual(counts["total"], 2)
        self.assertEqual(counts["secrets"], 1)
        self.assertEqual(counts["misconfigurations"], 1)
        self.assertTrue(manifest["result"]["scan_successful"])
        self.assertTrue(manifest["result"]["findings_detected"])
        self.assertEqual(manifest["result"]["status"], "completed")

    def test_findings_gate_only_trips_when_configured(self):
        configuration(self.repo, self.trivy, execution={"fail_on_findings": True})
        result = self.run_cli("run", "--event", "push", "--base-ref", self.first, expect=3)
        manifest = json.loads(result.stdout)
        self.assertEqual(manifest["result"]["status"], "completed")

    # -- scenario 14 -------------------------------------------------------
    def test_repeated_release_run_does_not_duplicate_publications(self):
        with MockServer() as server:
            server.routes["GET /api/v1/project"] = (200, [{"uuid": "rel-uuid", "name": "OVAC-Backend",
                                                          "version": "8.9.0"}], {})
            server.routes["PUT /api/v1/bom"] = (200, {"token": "tok"}, {})
            configuration(self.repo, self.trivy, integrations={"dependency_track": {"enabled": True}})
            env = {"DTRACK_URL": server.url, "DTRACK_API_KEY": "dt-key-value"}
            first = self.run_once("--event", "release", "--version", "8.9.0", env=env)
            second = self.run_once("--event", "release", "--version", "8.9.0", env=env)
            self.assertEqual(first["steps"]["dependency_track"]["status"], "PUBLISHED")
            self.assertIn(second["steps"]["dependency_track"]["status"], ("DUPLICATE", "SKIPPED"))
            uploads = [request for request in server.requests if request.path == "/api/v1/bom"]
            self.assertEqual(len(uploads), 1)

    # -- scenario 15 -------------------------------------------------------
    def test_untrusted_pull_request_runs_without_credentials_and_leaks_none(self):
        """The scan surface of the workflow: no token in the environment at all."""
        with MockServer() as server:
            configuration(self.repo, self.trivy, integrations={
                "dependency_track": {"enabled": True, "required": False},
                "defectdojo": {"enabled": True, "publish_trivy_reports": True},
                "barad_dur": {"enabled": True}})
            write_file(self.repo, "package-lock.json", json.dumps({"lockfileVersion": 3, "z": 3}) + "\n")
            commit_all(self.repo, "lockfile")
            enforced = {"DTRACK_URL": server.url, "DOJO_URL": server.url,
                        "BARAD_DUR_URL": server.url}
            manifest = self.run_once("--event", "pr", "--base-ref", self.first, env=enforced)
            self.assertEqual(server.requests, [])
        self.assertEqual(manifest["steps"]["dependency_track"]["reason"], "pull_request_is_temporary")
        self.assertEqual(manifest["steps"]["defectdojo"]["reason"], "pull_request_import_disabled")
        self.assertEqual(manifest["steps"]["barad_dur"]["status"], "PENDING")
        self.assertEqual(manifest["steps"]["barad_dur"]["reason"], "not_configured")
        message = json.dumps(manifest["steps"]["barad_dur"])
        self.assertIn("BARAD_DUR_TOKEN", message)          # names the variable
        run_dir = self.run_dir(manifest)
        for path in run_dir.iterdir():
            if path.is_file():
                self.assertNotIn("token-must-not-leak", path.read_text(errors="replace"),
                                 f"credential leaked into {path.name}")

    def test_trusted_pull_request_publishes_evidence_but_never_a_project(self):
        with MockServer() as server:
            server.routes["POST /api/v1/security-runs"] = (200, {"id": "pr-run"}, {})
            server.routes["POST /api/v1/security-runs/pr-run/artifacts"] = (200, {"ok": True}, {})
            server.routes["POST /api/v1/security-runs/pr-run/complete"] = (200, {"ok": True}, {})
            configuration(self.repo, self.trivy, integrations={"barad_dur": {"enabled": True}})
            write_file(self.repo, "package-lock.json", json.dumps({"lockfileVersion": 3, "w": 4}) + "\n")
            commit_all(self.repo, "lockfile")
            manifest = self.run_once("--event", "pr", "--base-ref", self.first, env={
                "BARAD_DUR_URL": server.url, "BARAD_DUR_TOKEN": "barad-token-value"})
            self.assertEqual(manifest["steps"]["barad_dur"]["status"], "PUBLISHED")
            self.assertEqual(manifest["steps"]["dependency_track"]["status"], "SKIPPED")
            self.assertFalse([request for request in server.requests
                              if request.path.startswith("/api/v1/project")])

    # -- scenario 16 -------------------------------------------------------
    def test_monorepo_analyses_only_the_configured_service(self):
        write_file(self.repo, "services/api/package.json", json.dumps({"name": "api", "version": "1.0.0"}) + "\n")
        write_file(self.repo, "services/api/src/index.ts", "export const a = 1;\n")
        write_file(self.repo, "services/web/package.json", json.dumps({"name": "web", "version": "2.0.0"}) + "\n")
        base = commit_all(self.repo, "monorepo")
        write_file(self.repo, "services/api/package.json", json.dumps({"name": "api", "version": "1.0.1"}) + "\n")
        write_file(self.repo, "services/web/src/app.tsx", "export const web = 2;\n")
        commit_all(self.repo, "both services")
        configuration(self.repo, self.trivy, project={
            "name": "OVAC", "service": "api", "ecosystem": "node", "path": "services/api"})
        manifest = self.run_once("--event", "push", "--base-ref", base)
        self.assertEqual(manifest["service"], "api")
        self.assertEqual(manifest["changes"]["files_changed"], ["services/api/package.json"])
        self.assertEqual(manifest["changes"]["files_ignored"], 1)
        self.assertEqual(manifest["security"]["target"], "services/api")


class SubdirectoryRepositoryTests(unittest.TestCase):
    """A configuration inside a service folder of a monorepo must still be correct.

    Diff paths are Git-root relative, so scoping and version comparison need the
    offset between the configured root and the Git top level. Without it, a change
    to a sibling service would be attributed to this one.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.repo = init_repo(self.root / "repo")
        write_file(self.repo, "services/api/package.json",
                   json.dumps({"name": "api", "version": "1.0.0"}, indent=2) + "\n")
        write_file(self.repo, "services/api/src/index.ts", "export const a = 1;\n")
        write_file(self.repo, "services/web/package.json",
                   json.dumps({"name": "web", "version": "2.0.0"}, indent=2) + "\n")
        self.trivy = install_fake_trivy(self.root / "bin")
        self.api = self.repo / "services" / "api"
        self.config = configuration(self.api, self.trivy)
        self.base = commit_all(self.repo, "monorepo")

    def tearDown(self):
        self._tmp.cleanup()

    def test_changes_are_attributed_from_the_git_root(self):
        write_file(self.repo, "services/api/package.json",
                   json.dumps({"name": "api", "version": "1.0.1"}, indent=2) + "\n")
        write_file(self.repo, "services/web/src/app.tsx", "export const web = 1;\n")
        commit_all(self.repo, "touch both services")
        result = run_cli(["run", "--event", "push", "--base-ref", self.base,
                          "--repository", str(self.api), "--config", str(self.config), "--json"],
                         cwd=self.repo)
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads(result.stdout)
        self.assertEqual(manifest["service"], "OVAC-Backend")
        self.assertEqual(manifest["git"]["repository_offset"], "services/api")
        self.assertEqual(manifest["changes"]["files_changed"], ["services/api/package.json"])
        self.assertEqual(manifest["changes"]["files_ignored"], 1)
        # Version comparison reads the file at the base commit from the Git root.
        self.assertTrue(manifest["changes"]["version_changed"])
        self.assertEqual(manifest["changes"]["previous_version"], "1.0.0")
        self.assertEqual(manifest["changes"]["current_version"], "1.0.1")


class ArtifactContractTests(ScenarioBase):
    def test_manifest_carries_every_required_field(self):
        manifest = self.run_once("--event", "push", "--base-ref", self.first)
        for key in ("schema_version", "run_id", "source", "event", "project", "service",
                    "application_version", "repository", "git", "timestamps", "changes",
                    "decisions", "steps", "result"):
            self.assertIn(key, manifest)
        self.assertEqual(manifest["schema_version"], "1.0")
        self.assertTrue(manifest["timestamps"]["started_at"].endswith("Z"))
        self.assertTrue(manifest["timestamps"]["finished_at"].endswith("Z"))
        self.assertEqual(manifest["git"]["commit_sha"], self.first)
        self.assertIn("counts", manifest["security"])
        self.assertIn("trivy_version", manifest["security"])
        self.assertEqual(manifest["security"]["trivy_version"], "0.76.1")
        self.assertIn("config", manifest)
        self.assertEqual(manifest["config"]["effective"]["trivy"]["scanners"],
                         ["vuln", "secret", "misconfig"])
        self.assertIn("artifacts", manifest)
        self.assertIn("trivy-report.json", manifest["artifacts"])
        self.assertEqual(len(manifest["artifacts"]["trivy-report.json"]["sha256"]), 64)

    def test_secret_evidence_is_redacted_outbound_but_kept_locally(self):
        manifest = self.run_once("--event", "push", "--base-ref", self.first)
        run_dir = self.run_dir(manifest)
        raw = (run_dir / "trivy-report.json").read_text()
        sanitized = (run_dir / "trivy-report.sanitized.json").read_text()
        self.assertIn("AKIAIOSFODNN7EXAMPLE", raw)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", sanitized)
        self.assertIn("CVE-2021-23337", sanitized)          # findings keep full fidelity
        self.assertEqual(manifest["security"]["outbound_redaction"]["redacted_fields"], 1)

    def test_execution_log_is_json_lines_with_the_run_id(self):
        manifest = self.run_once("--event", "push", "--base-ref", self.first)
        run_dir = self.run_dir(manifest)
        lines = (run_dir / "execution.log").read_text().splitlines()
        self.assertGreater(len(lines), 3)
        for line in lines:
            record = json.loads(line)
            self.assertEqual(record["run_id"], manifest["run_id"])
            self.assertTrue(record["timestamp"].endswith("Z"))
        events = [json.loads(line)["event"] for line in lines]
        self.assertIn("workflow_started", events)
        self.assertIn("workflow_finished", events)


if __name__ == "__main__":
    unittest.main()

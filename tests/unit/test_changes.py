"""Change detection and decision rules against real temporary Git repositories."""
import json
import tempfile
import unittest
from pathlib import Path

from barad_security.changes import detect_changes, matches_any, parse_name_status, parse_porcelain
from barad_security.config import build_config
from barad_security.decisions import evaluate
from barad_security.gitctx import detect_git_context
from barad_security.versioning import resolve_version
from tests.support import commit_all, init_repo, write_file

NODE_FILES = {
    "package.json": json.dumps({"name": "ovac-backend", "version": "8.8.0"}, indent=2) + "\n",
    "package-lock.json": json.dumps({"name": "ovac-backend", "version": "8.8.0", "lockfileVersion": 3}) + "\n",
    "Dockerfile": "FROM node:22-alpine\nCOPY . .\n",
    "src/index.ts": "export const hello = () => 'hi';\n",
}


class RepoTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = init_repo(Path(self._tmp.name) / "repo")
        for relative, content in NODE_FILES.items():
            write_file(self.repo, relative, content)
        write_file(self.repo, "barad-security.yml", "version: 1\nproject:\n  name: OVAC\n  service: OVAC-Backend\n  ecosystem: node\n")
        self.base = commit_all(self.repo, "initial")

    def tearDown(self):
        self._tmp.cleanup()

    def config(self, **overrides):
        document = {"version": 1, "project": {"name": "OVAC", "service": "OVAC-Backend", "ecosystem": "node"},
                    **overrides}
        return build_config(document, repo_root=self.repo, environ={})

    def analyse(self, config, *, event="push", base_ref=None, inventory_present=False, environ=None):
        context = detect_git_context(self.repo, event=event, base_ref=base_ref, environ=environ or {})
        version = resolve_version(config, environ={})
        report = detect_changes(config, context, version)
        decisions = evaluate(config, context, report, version, inventory_present=inventory_present)
        return context, report, decisions


class DecisionTests(RepoTestCase):
    def test_code_only_change_runs_trivy_and_skips_sbom(self):
        write_file(self.repo, "src/index.ts", "export const goodbye = () => 'bye';\n")
        commit_all(self.repo, "code only")
        _context, report, decisions = self.analyse(self.config(), base_ref=self.base, inventory_present=True)
        self.assertTrue(report.code_changed)
        self.assertFalse(report.dependency_changed)
        self.assertFalse(report.version_changed)
        self.assertFalse(report.build_context_changed)
        self.assertEqual(report.files_changed, ["src/index.ts"])
        self.assertTrue(decisions.run_trivy)
        self.assertFalse(decisions.generate_sbom)
        self.assertEqual(decisions.sbom_reason, "no_inventory_change")

    def test_lockfile_change_generates_sbom(self):
        write_file(self.repo, "package-lock.json", json.dumps({"name": "ovac-backend", "version": "8.8.0", "lockfileVersion": 3, "packages": {"node_modules/axios": {"version": "1.7.0"}}}) + "\n")
        commit_all(self.repo, "bump axios")
        _context, report, decisions = self.analyse(self.config(), base_ref=self.base, inventory_present=True)
        self.assertTrue(report.dependency_changed)
        self.assertEqual(report.files_changed, ["package-lock.json"])
        self.assertTrue(decisions.generate_sbom)
        self.assertEqual(decisions.sbom_reason, "dependency_changed")

    def test_pyproject_and_uv_lock_change_generates_sbom(self):
        write_file(self.repo, "backend/pyproject.toml", '[project]\nname = "api"\nversion = "1.0.0"\n')
        write_file(self.repo, "backend/uv.lock", "version = 1\n")
        commit_all(self.repo, "python deps")
        write_file(self.repo, "backend/uv.lock", "version = 1\n# changed\n")
        commit_all(self.repo, "update uv lock")
        _context, report, decisions = self.analyse(self.config(), base_ref="HEAD^", inventory_present=True)
        self.assertTrue(report.dependency_changed)
        self.assertIn("backend/uv.lock", report.files_changed)
        self.assertTrue(decisions.generate_sbom)

    def test_version_bump_in_package_json_is_distinguished(self):
        write_file(self.repo, "package.json", json.dumps({"name": "ovac-backend", "version": "8.9.0"}, indent=2) + "\n")
        commit_all(self.repo, "release 8.9.0")
        _context, report, decisions = self.analyse(self.config(), base_ref=self.base, inventory_present=True)
        self.assertTrue(report.version_changed)
        self.assertEqual((report.previous_version, report.current_version), ("8.8.0", "8.9.0"))
        self.assertTrue(decisions.generate_sbom)
        self.assertEqual(decisions.sbom_reason, "application_version_changed")

    def test_dockerfile_change_is_build_context(self):
        write_file(self.repo, "Dockerfile", "FROM node:24-alpine\nCOPY . .\n")
        commit_all(self.repo, "new base image")
        _context, report, decisions = self.analyse(self.config(), base_ref=self.base, inventory_present=True)
        self.assertTrue(report.build_context_changed)
        self.assertFalse(report.dependency_changed)
        self.assertEqual(decisions.sbom_reason, "build_context_changed")

    def test_release_event_generates_sbom_without_any_dependency_change(self):
        write_file(self.repo, "src/index.ts", "export const hello = () => 'release';\n")
        commit_all(self.repo, "release prep")
        _context, report, decisions = self.analyse(self.config(), event="release", base_ref=self.base,
                                                   inventory_present=True, environ={})
        self.assertFalse(report.dependency_changed)
        self.assertTrue(decisions.generate_sbom)
        self.assertEqual(decisions.sbom_reason, "release_event")

    def test_sbom_triggers_can_be_switched_off_explicitly(self):
        write_file(self.repo, "package-lock.json", json.dumps({"lockfileVersion": 3, "changed": True}) + "\n")
        commit_all(self.repo, "lockfile")
        config = self.config(sbom={"generate_on": {"dependency_changes": False}})
        _context, _report, decisions = self.analyse(config, base_ref=self.base, inventory_present=True)
        self.assertFalse(decisions.generate_sbom)
        codes = {reason["code"] for reason in decisions.reasons}
        self.assertIn("dependency_changed_suppressed", codes)

    def test_missing_base_reference_is_conservative(self):
        config = self.config()
        context = detect_git_context(self.repo, event="pr", base_ref="does-not-exist", environ={})
        self.assertFalse(context.base_sha)
        self.assertEqual(context.base_resolution, "unavailable")
        report = detect_changes(config, context, resolve_version(config, environ={}))
        decisions = evaluate(config, context, report, None, inventory_present=True)
        self.assertTrue(decisions.generate_sbom)
        self.assertEqual(decisions.sbom_reason, "base_reference_unavailable")

    def test_no_previous_inventory_forces_generation(self):
        _context, _report, decisions = self.analyse(self.config(), base_ref=self.base, inventory_present=False)
        self.assertTrue(decisions.generate_sbom)
        self.assertEqual(decisions.sbom_reason, "initial_inventory_missing")

    def test_disabled_sbom_never_generates(self):
        config = self.config(sbom={"enabled": False})
        write_file(self.repo, "package-lock.json", json.dumps({"lockfileVersion": 3, "x": 1}) + "\n")
        commit_all(self.repo, "lockfile")
        _context, _report, decisions = self.analyse(config, base_ref=self.base, inventory_present=False)
        self.assertFalse(decisions.generate_sbom)
        self.assertEqual(decisions.sbom_reason, "sbom_disabled")

    def test_pull_request_covers_every_commit_of_the_branch(self):
        write_file(self.repo, "package-lock.json", json.dumps({"lockfileVersion": 3, "a": 1}) + "\n")
        commit_all(self.repo, "first")
        write_file(self.repo, "src/index.ts", "export const x = 1;\n")
        commit_all(self.repo, "second")
        context = detect_git_context(self.repo, event="pr", base_ref=self.base, environ={})
        report = detect_changes(self.config(), context, resolve_version(self.config(), environ={}))
        self.assertIn("package-lock.json", report.files_changed)
        self.assertIn("src/index.ts", report.files_changed)
        self.assertTrue(report.dependency_changed)
        self.assertTrue(context.base_resolution.startswith("merge_base_of_"))

    def test_option_shaped_base_reference_never_reaches_git(self):
        context = detect_git_context(self.repo, event="pr", base_ref="--upload-pack=/bin/sh", environ={})
        self.assertIsNone(context.base_sha)
        self.assertEqual(context.base_resolution, "unavailable")
        self.assertIn("base_ref_rejected", {problem["code"] for problem in context.problems})
        report = detect_changes(self.config(), context, resolve_version(self.config(), environ={}))
        decisions = evaluate(self.config(), context, report, None, inventory_present=True)
        self.assertTrue(decisions.generate_sbom)
        self.assertEqual(decisions.sbom_reason, "base_reference_unavailable")
        # The rejected reference is recorded as a problem, never as a base to compare against.
        self.assertIsNone(context.base_ref)
        rejected = [problem for problem in context.problems if problem["code"] == "base_ref_rejected"][0]
        self.assertIn("upload-pack", rejected["detail"])

    def test_monorepo_attributes_changes_to_the_right_service(self):
        write_file(self.repo, "services/api/package.json", json.dumps({"name": "api", "version": "1.0.0"}) + "\n")
        write_file(self.repo, "services/api/src/index.ts", "export const a = 1;\n")
        write_file(self.repo, "services/web/package.json", json.dumps({"name": "web", "version": "2.0.0"}) + "\n")
        base = commit_all(self.repo, "monorepo")
        write_file(self.repo, "services/api/package.json", json.dumps({"name": "api", "version": "1.0.1"}) + "\n")
        write_file(self.repo, "services/web/src/app.tsx", "export const web = 1;\n")
        commit_all(self.repo, "touch both services")
        config = build_config(
            {"version": 1,
             "project": {"name": "OVAC", "service": "api", "ecosystem": "node", "path": "services/api",
                         "version": {"source": "package-json"}}},
            repo_root=self.repo, environ={})
        context = detect_git_context(self.repo, event="push", base_ref=base, environ={})
        report = detect_changes(config, context, resolve_version(config, environ={}))
        self.assertEqual(report.files_changed, ["services/api/package.json"])
        self.assertEqual(report.ignored, ["services/web/src/app.tsx"])
        self.assertTrue(report.version_changed)

    def test_related_paths_extend_the_scope(self):
        write_file(self.repo, "packages/shared/index.ts", "export const s = 1;\n")
        base = commit_all(self.repo, "shared")
        write_file(self.repo, "packages/shared/index.ts", "export const s = 2;\n")
        commit_all(self.repo, "shared change")
        config = build_config(
            {"version": 1,
             "project": {"name": "OVAC", "service": "OVAC-Backend", "ecosystem": "node",
                         "related_paths": ["packages/shared"]}},
            repo_root=self.repo, environ={})
        context = detect_git_context(self.repo, event="push", base_ref=base, environ={})
        report = detect_changes(config, context, resolve_version(config, environ={}))
        self.assertEqual(report.files_changed, ["packages/shared/index.ts"])
        self.assertTrue(report.code_changed)


class PublicationPlanTests(RepoTestCase):
    def plan(self, config, event, **kwargs):
        context = detect_git_context(self.repo, event=event, base_ref=self.base, environ={})
        report = detect_changes(config, context, resolve_version(config, environ={}))
        # A fresh inventory forces SBOM generation so the publication plan is observable.
        decisions = evaluate(config, context, report, None, inventory_present=False)
        return decisions.publications

    def test_pull_request_never_publishes_dependency_track(self):
        config = self.config(integrations={"dependency_track": {"enabled": True}})
        plan = self.plan(config, "pr")
        self.assertEqual(plan["dependency_track"]["action"], "skip")
        self.assertEqual(plan["dependency_track"]["reason"], "pull_request_is_temporary")

    def test_development_publication_requires_the_opt_in(self):
        config = self.config(integrations={"dependency_track": {"enabled": True}})
        self.assertEqual(self.plan(config, "push")["dependency_track"]["reason"], "not_a_release")
        config = self.config(integrations={"dependency_track": {"enabled": True,
                                                                "update_development_project": True}})
        plan = self.plan(config, "push")
        self.assertEqual(plan["dependency_track"]["action"], "publish")
        self.assertEqual(plan["dependency_track"]["target"], "development")

    def test_release_publishes_dependency_track(self):
        config = self.config(integrations={"dependency_track": {"enabled": True}})
        plan = self.plan(config, "release")
        self.assertEqual(plan["dependency_track"]["target"], "release")

    def test_defectdojo_skips_pull_requests_by_default(self):
        config = self.config(integrations={"defectdojo": {"enabled": True, "publish_trivy_reports": True}})
        self.assertEqual(self.plan(config, "pr")["defectdojo"]["reason"], "pull_request_import_disabled")
        self.assertEqual(self.plan(config, "push")["defectdojo"]["action"], "publish")

    def test_services_are_off_unless_enabled(self):
        plan = self.plan(self.config(), "release")
        self.assertEqual(plan["barad_dur"]["reason"], "integration_disabled")
        self.assertEqual(plan["defectdojo"]["reason"], "integration_disabled")


class ParserTests(unittest.TestCase):
    def test_name_status_rename_parsing(self):
        parsed = parse_name_status("A\0new.txt\0R100\0old.lock\0new.lock\0")
        self.assertEqual(parsed, [("A", "new.txt", None), ("R", "new.lock", "old.lock")])

    def test_porcelain_rename_parsing(self):
        parsed = parse_porcelain("R  new.lock\0old.lock\0 M src/a.ts\0")
        self.assertEqual(parsed, [("R", "new.lock", "old.lock"), ("M", "src/a.ts", None)])

    def test_pattern_matching_variants(self):
        self.assertEqual(matches_any("package-lock.json", ["**/package-lock.json"]), "**/package-lock.json")
        self.assertEqual(matches_any("a/b/package-lock.json", ["**/package-lock.json"]), "**/package-lock.json")
        self.assertEqual(matches_any("uv.lock", ["uv.lock"]), "uv.lock")
        self.assertEqual(matches_any("requirements/dev.txt", ["requirements/*.txt"]), "requirements/*.txt")
        self.assertIsNone(matches_any("src/app.ts", ["**/package-lock.json"]))


if __name__ == "__main__":
    unittest.main()

import json
import subprocess
import unittest
from pathlib import Path

from cli_support import CliTestCase, FakeTrivy, cyclonedx, fixed_purl_sbom, graph_sbom


class ProjectAndInventoryTests(CliTestCase):
    def test_project_identity_version_and_ecosystems_are_automatic(self):
        self.write("pyproject.toml", '[project]\nname = "demo"\nversion = "1.2.3"\n')
        self.write("web/package.json", '{"name": "web"}\n')
        self.write("Dockerfile", "FROM scratch\n")

        code, out, err, manifest, run_dir = self.scan(cwd=self.root)

        self.assertEqual(code, 0, err)
        self.assertEqual(manifest["project"]["name"], self.root.name)
        self.assertEqual(manifest["project"]["name_source"], "directory")
        self.assertEqual(
            manifest["project"]["ecosystems"], ["node", "python", "container"]
        )
        self.assertEqual(manifest["application_version"]["value"], "1.2.3")

    def test_git_metadata_is_optional_but_captured_when_present(self):
        self.write("README.md", "demo\n")
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "add", "README.md"], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "-c",
                "user.email=test@example.com",
                "-c",
                "user.name=Test",
                "commit",
                "-q",
                "-m",
                "init",
            ],
            check=True,
        )
        head = subprocess.check_output(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"], text=True
        ).strip()

        code, out, err, manifest, run_dir = self.scan(cwd=self.root)

        self.assertEqual(code, 0, err)
        self.assertTrue(manifest["git"]["available"])
        self.assertEqual(manifest["commit"], head)
        self.assertEqual(manifest["git"]["commit"], head)
        self.assertEqual(manifest["project"]["name_source"], "git")

    def test_previous_snapshot_is_local_only_and_detects_change(self):
        self.write("pyproject.toml", '[project]\nname = "demo"\nversion = "1.2.3"\n')

        code, out, err, first, first_dir = self.scan(cwd=self.root)
        self.assertEqual(code, 0, err)
        self.assertEqual(first["inventory"]["comparison"], "no_previous")

        code, out, err, second, second_dir = self.scan(cwd=self.root)
        self.assertEqual(code, 0, err)
        self.assertEqual(second["inventory"]["comparison"], "unchanged")
        self.assertEqual(
            second["inventory"]["fingerprint"], first["inventory"]["fingerprint"]
        )
        self.assertEqual(second["inventory"]["previous"]["source"], "local_snapshot")
        self.assertTrue(second["inventory"]["previous"]["compatible"])
        self.assertEqual(
            second["inventory"]["publication"],
            {"claimed": False, "basis": "local_snapshot_only"},
        )

        FakeTrivy.sbom = cyclonedx(version="2.0.0")
        code, out, err, third, third_dir = self.scan(cwd=self.root)
        self.assertEqual(code, 0, err)
        self.assertEqual(third["inventory"]["comparison"], "changed")
        self.assertEqual(
            third["inventory"]["previous"]["fingerprint"],
            second["inventory"]["fingerprint"],
        )

    def test_unverifiable_previous_snapshot_is_not_reported_unchanged(self):
        code, out, err, first, first_dir = self.scan(cwd=self.root)
        self.assertEqual(code, 0, err)
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        project = next(iter(state["targets"].values()))
        record = next(iter(project.values()))
        record.pop("inventory_fingerprint", None)
        self.state_path.write_text(json.dumps(state), encoding="utf-8")

        code, out, err, second, second_dir = self.scan(cwd=self.root)

        self.assertEqual(code, 0, err)
        self.assertEqual(second["inventory"]["comparison"], "unverifiable")
        self.assertFalse(second["inventory"]["previous"]["compatible"])

    def test_dependency_edge_changes_are_detected(self):
        FakeTrivy.sbom = graph_sbom(edge=True)
        code, out, err, first, first_dir = self.scan(cwd=self.root)
        self.assertEqual(code, 0, err)
        self.assertEqual(first["inventory"]["comparison"], "no_previous")

        FakeTrivy.sbom = graph_sbom(edge=False)
        code, out, err, second, second_dir = self.scan(cwd=self.root)

        self.assertEqual(code, 0, err)
        self.assertNotEqual(
            second["inventory"]["fingerprint"], first["inventory"]["fingerprint"]
        )
        self.assertEqual(second["inventory"]["comparison"], "changed")

    def test_bom_ref_renames_do_not_change_the_graph_fingerprint(self):
        FakeTrivy.sbom = graph_sbom(app_ref="ref-app", lib_ref="ref-lib")
        code, out, err, first, first_dir = self.scan(cwd=self.root)
        self.assertEqual(code, 0, err)

        FakeTrivy.sbom = graph_sbom(app_ref="node-1", lib_ref="node-2")
        code, out, err, second, second_dir = self.scan(cwd=self.root)

        self.assertEqual(code, 0, err)
        self.assertEqual(
            second["inventory"]["fingerprint"], first["inventory"]["fingerprint"]
        )
        self.assertEqual(second["inventory"]["comparison"], "unchanged")

    def test_remote_export_rewrites_metadata_root_without_inventory_change(self):
        from barad.core.inventory import fingerprint
        local = graph_sbom()
        local['metadata']['component'] = {'bom-ref': 'local-root', 'name': '/scan'}
        local['dependencies'].append({'ref': 'local-root', 'dependsOn': ['ref-app']})
        remote = graph_sbom(app_ref='new-app', lib_ref='new-lib')
        remote['metadata']['component'] = {'bom-ref': 'remote-project-uuid', 'name': 'remote-project'}
        remote['dependencies'].append({'ref': 'remote-project-uuid', 'dependsOn': ['new-app']})
        self.assertEqual(fingerprint(local, target_type='fs', target='.'),
                         fingerprint(remote, target_type='fs', target='.'))

    def test_same_purl_with_changed_version_changes_the_fingerprint(self):
        FakeTrivy.sbom = fixed_purl_sbom("1.0.0")
        code, out, err, first, first_dir = self.scan(cwd=self.root)
        self.assertEqual(code, 0, err)

        FakeTrivy.sbom = fixed_purl_sbom("2.0.0")
        code, out, err, second, second_dir = self.scan(cwd=self.root)

        self.assertEqual(code, 0, err)
        self.assertNotEqual(
            second["inventory"]["fingerprint"], first["inventory"]["fingerprint"]
        )
        self.assertEqual(second["inventory"]["comparison"], "changed")

    def test_distinct_image_targets_do_not_alias(self):
        FakeTrivy.sbom = graph_sbom()
        self.write_config(
            "version: 1\n"
            "project:\n  name: image-project\n"
            "scan:\n"
            "  target_type: image\n"
            "  runner: local\n"
            "  target: ghcr.io/acme/app@sha256:aaa\n"
        )
        code, out, err, first, first_dir = self.scan(cwd=self.root)
        self.assertEqual(code, 0, err)
        self.assertEqual(first["inventory"]["comparison"], "no_previous")

        self.write_config(
            "version: 1\n"
            "project:\n  name: image-project\n"
            "scan:\n"
            "  target_type: image\n"
            "  runner: local\n"
            "  target: ghcr.io/acme/app@sha256:bbb\n"
        )
        code, out, err, second, second_dir = self.scan(cwd=self.root)

        self.assertEqual(code, 0, err)
        self.assertEqual(second["inventory"]["comparison"], "no_previous")
        self.assertNotEqual(
            second["inventory"]["fingerprint"], first["inventory"]["fingerprint"]
        )

    def test_nondeterministic_cyclonedx_metadata_does_not_change_fingerprint(self):
        FakeTrivy.sbom = cyclonedx(serial="urn:uuid:aaa", timestamp="2024-01-01T00:00:00Z")
        code, out, err, first, first_dir = self.scan(cwd=self.root)
        self.assertEqual(code, 0, err)

        FakeTrivy.sbom = cyclonedx(serial="urn:uuid:bbb", timestamp="2025-09-09T09:09:09Z")
        FakeTrivy.sbom["metadata"]["tools"]["components"][0]["version"] = "9.9.9"
        code, out, err, second, second_dir = self.scan(cwd=self.root)

        self.assertEqual(code, 0, err)
        self.assertEqual(
            second["inventory"]["fingerprint"], first["inventory"]["fingerprint"]
        )
        self.assertEqual(second["inventory"]["comparison"], "unchanged")


if __name__ == "__main__":
    unittest.main()

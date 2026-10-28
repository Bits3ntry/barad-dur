"""Tests for the Dependency-Track upload plan (pure, no network)."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.sbom.upload_all import (  # noqa: E402
    DEFAULT_EXCLUDES, family_of, parent_for, plan, project_name_of,
)


def entry(project, name, version, status="ok", runtime="node 24"):
    return {"project": project, "name": name, "version": version,
            "status": status, "runtime": runtime, "sbom": f"artifacts/sbom/{name}.cdx.json"}


class NamingTests(unittest.TestCase):
    def test_family_is_the_first_path_segment_lowercased(self):
        self.assertEqual(family_of("shutter/shutter-api"), "shutter")
        self.assertEqual(family_of("OVAC/councilbox-server"), "ovac")

    def test_project_name_comes_from_the_repository_not_package_json(self):
        self.assertEqual(project_name_of("OVAC/councilbox-server", "api"), "councilbox-server")

    def test_nested_projects_flatten_without_colliding(self):
        self.assertEqual(project_name_of("shutter/shutter-api/sdk", "sdk"), "shutter-api-sdk")
        self.assertEqual(project_name_of("services/x/src/ux", "ux"), "x-ux")

    def test_parent_reuses_an_existing_name_whatever_its_casing(self):
        self.assertEqual(parent_for("ovac", ["OVAC", "SHUTTER"]), "OVAC")
        self.assertEqual(parent_for("shutter", ["OVAC", "SHUTTER"]), "SHUTTER")

    def test_parent_is_uppercased_when_it_does_not_exist_yet(self):
        self.assertEqual(parent_for("services", ["OVAC"]), "SERVICES")


class PlanTests(unittest.TestCase):
    def test_child_keeps_the_version_in_its_version_field(self):
        uploads, _ = plan([entry("shutter/shutter-api", "shutter-api", "1.25.0")])
        self.assertEqual(uploads[0]["name"], "shutter-api")
        self.assertEqual(uploads[0]["version"], "1.25.0")
        self.assertEqual(uploads[0]["parent_name"], "SHUTTER")

    def test_two_versions_of_one_component_become_siblings(self):
        uploads, _ = plan([
            entry("shutter/shutter-api", "shutter-api", "1.25.0"),
            entry("shutter/shutter-api", "shutter-api", "1.26.0"),
        ])
        self.assertEqual([u["version"] for u in uploads], ["1.25.0", "1.26.0"])
        self.assertEqual({u["name"] for u in uploads}, {"shutter-api"})

    def test_two_repos_sharing_a_package_name_do_not_collide(self):
        # Real defect: both declare name "api" version 21.7.2 in OVAC.
        uploads, _ = plan([
            entry("OVAC/councilbox-server", "api", "21.7.2"),
            entry("OVAC/another-server", "api", "21.7.2"),
        ])
        self.assertEqual(sorted(u["name"] for u in uploads), ["another-server", "councilbox-server"])

    def test_excluded_repositories_are_reported_not_uploaded(self):
        uploads, excluded = plan([
            entry("OVAC/councilbox-server-license-limit", "api", "21.7.2"),
            entry("OVAC/councilbox-server", "api", "21.7.2"),
        ])
        self.assertEqual([u["name"] for u in uploads], ["councilbox-server"])
        self.assertEqual(excluded, ["OVAC/councilbox-server-license-limit"])

    def test_license_limit_is_excluded_by_default(self):
        self.assertIn("OVAC/councilbox-server-license-limit", DEFAULT_EXCLUDES)

    def test_failed_entries_are_skipped(self):
        uploads, _ = plan([entry("a/b", "b", "1", status="failed")])
        self.assertEqual(uploads, [])

    def test_missing_version_gets_an_explicit_placeholder(self):
        uploads, _ = plan([entry("a/b", "b", None)])
        self.assertEqual(uploads[0]["version"], "0.0.0-unknown")

    def test_entries_are_ordered_by_parent_then_name(self):
        uploads, _ = plan([
            entry("shutter/z-api", "z-api", "1"),
            entry("EVID/b-evid", "b-evid", "1"),
            entry("shutter/a-api", "a-api", "1"),
        ])
        self.assertEqual([(u["parent_name"], u["name"]) for u in uploads],
                         [("EVID", "b-evid"), ("SHUTTER", "a-api"), ("SHUTTER", "z-api")])

    def test_duplicate_identities_abort_the_plan(self):
        with self.assertRaises(SystemExit) as ctx:
            plan([
                # Different paths that flatten to the same project name.
                entry("a/same/one", "x", "1"),
                entry("b/same-one", "y", "1"),
            ])
        self.assertIn("duplicate", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()

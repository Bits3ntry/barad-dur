"""One real end-to-end run with the pinned Trivy container (no fakes).

Skipped when Docker or the pinned image is unavailable, and reported as skipped —
never as proof. The assertions are about behaviour, not about a fixed CVE count:
an advisory mirror keeps moving, so the test proves that a real report was parsed,
that components were inventoried and that the SBOM rule reacted to the change.
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import yaml

from tests.support import REPO_ROOT, commit_all, docker_available, init_repo, run_cli, write_file

TRIVY_IMAGE = "aquasec/trivy:0.76.1"
EXAMPLE = REPO_ROOT / "examples" / "node"


@unittest.skipUnless(docker_available(TRIVY_IMAGE), f"docker image {TRIVY_IMAGE} is not available")
class RealTrivyEndToEnd(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = init_repo(Path(self._tmp.name) / "repo")
        for source in EXAMPLE.rglob("*"):
            if source.is_file() and ".barad-dur" not in source.parts:
                target = self.repo / source.relative_to(EXAMPLE)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
        self.config = self.repo / "barad-security.yml"
        document = yaml.safe_load(self.config.read_text())
        document["trivy"]["runner"] = "docker"
        document["trivy"]["image"] = TRIVY_IMAGE
        document["trivy"]["cache_enabled"] = True
        document["trivy"]["timeout_seconds"] = 900
        self.config.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        self.base = commit_all(self.repo, "initial")

    def tearDown(self):
        self._tmp.cleanup()

    def run_repo(self, *args, expect=0):
        result = run_cli(["run", *args, "--repository", str(self.repo), "--config", str(self.config),
                          "--json"], cwd=REPO_ROOT, timeout=1800)
        self.assertEqual(result.returncode, expect, f"stdout={result.stdout}\nstderr={result.stderr}")
        return json.loads(result.stdout)

    def test_real_scan_inventories_the_service_and_skips_the_sbom_when_code_changes(self):
        first = self.run_repo("--event", "push", "--base-ref", self.base)
        self.assertEqual(first["steps"]["trivy"]["status"], "SUCCESS")
        self.assertTrue(first["security"]["scan_successful"])
        self.assertEqual(first["security"]["trivy_version"], "0.76.1")
        # A real advisory database always has something to say about lodash 4.17.20.
        self.assertGreaterEqual(first["security"]["counts"]["total"], 1)
        self.assertEqual(first["steps"]["sbom"]["status"], "SUCCESS")
        validation = first["steps"]["sbom"]["validation"]
        self.assertTrue(validation["ok"])
        self.assertEqual(validation["summary"]["bom_format"], "CycloneDX")
        self.assertGreaterEqual(validation["summary"]["components"], 2)
        self.assertGreaterEqual(validation["summary"]["components_with_purl"], 2)
        run_dir = sorted((self.repo / ".barad-dur" / "security" / "runs").iterdir())[-1]
        report = json.loads((run_dir / "trivy-report.json").read_text())
        self.assertTrue(report.get("Results"))
        sbom = json.loads((run_dir / "sbom.cdx.json").read_text())
        purls = [component.get("purl") for component in sbom["components"] if component.get("purl")]
        self.assertTrue(any("lodash" in purl for purl in purls), purls)
        self.assertEqual(sbom.get("vulnerabilities", []), [])

        write_file(self.repo, "src/index.ts", "export const health = () => ({ status: 'real' });\n")
        commit_all(self.repo, "code only")
        second = self.run_repo("--event", "push", "--base-ref", "HEAD^")
        self.assertEqual(second["steps"]["trivy"]["status"], "SUCCESS")
        self.assertNotIn("sbom", second["steps"])
        self.assertEqual(second["decisions"]["sbom_reason"], "no_inventory_change")


if __name__ == "__main__":
    unittest.main()

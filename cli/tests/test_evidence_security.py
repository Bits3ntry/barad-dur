import json
import os
import stat
import subprocess
import unittest

from support import REPO_ROOT, CliTestCase

PRESERVED_GITIGNORE_LINES = [
    "__pycache__/",
    "!.env.example",
    ".env",
    ".env.*",
    ".pytest_cache/",
    ".secrets/",
    ".venv/",
    "*.pyc",
    "artifacts/",
    "backups/",
]


def mode(path):
    return stat.S_IMODE(path.stat().st_mode)


@unittest.skipUnless(os.name == "posix", "POSIX permission contract")
class EvidencePermissionTests(CliTestCase):
    def test_run_state_and_parent_directories_are_private(self):
        code, out, err, manifest, run_dir = self.scan(cwd=self.root)

        self.assertEqual(code, 0, err)
        for directory in (run_dir, self.state_path.parent, self.root / ".barad",
                          self.default_output):
            self.assertEqual(mode(directory), 0o700, directory)

    def test_evidence_and_state_files_are_private(self):
        code, out, err, manifest, run_dir = self.scan(cwd=self.root)

        self.assertEqual(code, 0, err)
        evidence = [path for path in run_dir.iterdir() if path.is_file()]
        self.assertGreaterEqual(len(evidence), 4)
        for path in evidence:
            self.assertEqual(mode(path), 0o600, path)
        self.assertEqual(mode(self.state_path), 0o600)
        self.assertEqual(manifest["scan"]["evidence_protection"]["unprotected"], [])

    def test_scan_with_local_env_and_secrets_keeps_evidence_private(self):
        self.write(".env", "TOKEN=supersecret123\n")
        self.write(".secrets/deploy.key", "supersecret123\n")
        self.write("pyproject.toml", '[project]\nname = "demo"\nversion = "1.2.3"\n')

        code, out, err, manifest, run_dir = self.scan(cwd=self.root)

        self.assertEqual(code, 0, err)
        self.assertEqual(mode(run_dir), 0o700)
        self.assertEqual(mode(run_dir / "security.json"), 0o600)
        self.assertNotIn("supersecret123", json.dumps(manifest))
        self.assertNotIn("supersecret123", self.state_path.read_text(encoding="utf-8"))
        for name in ("manifest.json", "security.sanitized.json", "execution.log"):
            self.assertNotIn("supersecret123", (run_dir / name).read_text(encoding="utf-8"))
        self.assertTrue((self.root / ".env").is_file())
        self.assertTrue((self.root / ".secrets" / "deploy.key").is_file())


class GitIgnoreTests(unittest.TestCase):
    def test_barad_is_ignored_without_changing_existing_lines(self):
        lines = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()

        self.assertEqual(lines[:len(PRESERVED_GITIGNORE_LINES)],
                         PRESERVED_GITIGNORE_LINES)
        self.assertEqual(lines.count(".barad/"), 1)
        self.assertEqual(lines[-1], ".barad/")

        for candidate in (".barad/reports/scan-test/security.json",
                          ".barad/state/local-inventory.json"):
            result = subprocess.run(
                ["git", "-C", str(REPO_ROOT), "check-ignore", "-v", candidate],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(".barad/", result.stdout)


if __name__ == "__main__":
    unittest.main()

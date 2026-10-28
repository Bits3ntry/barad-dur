"""Black-box contract tests for the single-stack Compose project."""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "compose.yaml"
SECRETS = {
    "DT_DB_PASSWORD": "test-dt-db",
    "DD_DB_PASSWORD": "test-dojo-db",
    "DD_SECRET_KEY": "test-secret-key",
    "DD_CREDENTIAL_AES_256_KEY": "test-aes-key",
    "TRIVY_SERVER_TOKEN": "test-trivy-token",
}
SCANNERS = {"trivy", "syft", "cyclonedx"}


def compose(*args, secrets=None, profile=None):
    """Run compose against a temporary env file so a local .env cannot leak in."""
    with tempfile.TemporaryDirectory() as directory:
        env_file = Path(directory) / "test.env"
        env_file.write_text("".join(f"{k}={v}\n" for k, v in (secrets or {}).items()), encoding="utf-8")
        cmd = ["docker", "compose", "--env-file", str(env_file), "-f", str(COMPOSE)]
        if profile:
            cmd += ["--profile", profile]
        cmd += list(args)
        isolated = {k: v for k, v in os.environ.items() if not k.startswith(("DT_", "DD_"))}
        return subprocess.run(cmd, cwd=ROOT, env=isolated, capture_output=True, text=True)


class StackContractTests(unittest.TestCase):
    def test_stack_refuses_to_start_without_every_secret(self):
        rejected = compose("config", "--quiet")
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual(rejected.stdout, "")
        for name in SECRETS:
            self.assertIn(name, rejected.stderr)
        accepted = compose("config", "--quiet", secrets=SECRETS)
        self.assertEqual((accepted.returncode, accepted.stderr), (0, ""))

    def test_only_loopback_user_interfaces_publish_ports(self):
        result = compose("config", "--format", "json", secrets=SECRETS, profile="tools")
        self.assertEqual(result.returncode, 0, result.stderr)
        services = json.loads(result.stdout)["services"]
        published = {name: svc["ports"] for name, svc in services.items() if svc.get("ports")}
        self.assertEqual(set(published), {"dt-apiserver", "dt-frontend", "dojo-nginx"})
        for name, ports in published.items():
            for port in ports:
                self.assertEqual(port["host_ip"], "127.0.0.1", f"{name} leaks beyond loopback")
        for internal in ("dt-postgres", "dojo-postgres", "dojo-valkey", "trivy", "syft",
                         "cyclonedx", "trivy-server"):
            self.assertNotIn("ports", services[internal], f"{internal} must not publish a port")

    def test_scanners_are_opt_in_not_always_running(self):
        default = compose("config", "--services", secrets=SECRETS)
        self.assertEqual(default.returncode, 0, default.stderr)
        self.assertFalse(SCANNERS & set(default.stdout.split()))
        # Dependency-Track needs Trivy as an always-on analyzer, so it is not opt-in.
        self.assertIn("trivy-server", default.stdout.split())
        self.assertIn("dojo-nginx", default.stdout)
        self.assertIn("dt-apiserver", default.stdout)
        with_tools = compose("config", "--services", secrets=SECRETS, profile="tools")
        self.assertEqual(with_tools.returncode, 0, with_tools.stderr)
        self.assertLessEqual(SCANNERS, set(with_tools.stdout.split()))

    def test_single_compose_project_owns_the_whole_stack(self):
        result = compose("config", "--format", "json", secrets=SECRETS, profile="tools")
        data = json.loads(result.stdout)
        self.assertEqual(data["name"], "barad-dur")
        self.assertFalse((ROOT / "infrastructure" / "defectdojo" / "compose.yaml").exists(),
                         "a second Compose project must not resurface")

    def test_trivy_rejects_mutable_image_without_creating_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "not-created"
            result = subprocess.run(
                ["sh", str(ROOT / "scripts" / "scanners" / "trivy.sh"), "image", "example:latest", str(path)],
                cwd=ROOT, capture_output=True, text=True)
            self.assertEqual((result.returncode, result.stdout, result.stderr),
                             (2, "", "image must be pinned as name@sha256:digest; mutable tags are refused\n"))
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()

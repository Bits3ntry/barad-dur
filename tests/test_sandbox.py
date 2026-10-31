"""Sandbox contract: the flags that isolate a worker scan are not optional."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "cli"))

from barad import sandbox  # noqa: E402

IMAGE = "python@sha256:" + "a" * 64


class SandboxContractTest(unittest.TestCase):
    def setUp(self):
        self.target = Path("/tmp/barad-sandbox-unit/src")
        self.target.mkdir(parents=True, exist_ok=True)
        (self.target / "app.py").write_text("print(1)\n")
        self.output = Path("/tmp/barad-sandbox-unit/out")

    def test_isolation_flags_are_present(self):
        command = sandbox.build_command(IMAGE, ["barad", "run", "/target"],
                                        "/target", self.target, self.output)
        joined = " ".join(command)
        for flag in ["--network none", "--read-only", "--cap-drop ALL",
                     "--security-opt no-new-privileges", "--user 65534:65534",
                     "--memory 1g", "--cpus 1", "--pids-limit 256"]:
            self.assertIn(flag, joined)
        self.assertIn("--tmpfs /tmp:rw,noexec,nosuid,size=256m", joined)
        self.assertIn(f"{self.target.resolve()}:/target:ro", joined)
        self.assertIn(f"{self.output.resolve()}:/out:rw", joined)

    def test_unpinned_image_is_refused(self):
        for image in ("python:3.12-slim", "nginx", "python@sha256:abc"):
            with self.assertRaises(sandbox.SandboxError):
                sandbox.build_command(image, ["x"], "/t", self.target,
                                      self.output)

    def test_docker_socket_cannot_be_exposed(self):
        with self.assertRaises(sandbox.SandboxError):
            sandbox.build_command(IMAGE, ["-v", "/var/run/docker.sock:/sock"],
                                  "/t", self.target, self.output)

    def test_empty_command_is_refused(self):
        with self.assertRaises(sandbox.SandboxError):
            sandbox.build_command(IMAGE, [], "/t", self.target, self.output)

    def test_missing_target_is_refused(self):
        with self.assertRaises(sandbox.SandboxError):
            sandbox.build_command(IMAGE, ["barad"], "/t",
                                  Path("/tmp/barad-sandbox-unit/nope"),
                                  self.output)

    def test_worker_passes_the_image_through(self):
        from barad import worker

        captured = {}

        def fake_run(command, timeout=900):
            captured["command"] = command
            return 0, '{"counts": {"findings": 0}}', ""

        original_build = sandbox.build_command
        original_run = sandbox.run
        sandbox.build_command = lambda image, argv, workdir, target, out: [
            "docker", "run", image, *argv]
        sandbox.run = fake_run
        try:
            manifest = worker.run_scan(self.target, self.output,
                                       isolate_image=IMAGE)
        finally:
            sandbox.build_command = original_build
            sandbox.run = original_run
        self.assertEqual(manifest["counts"]["findings"], 0)
        self.assertEqual(captured["command"][2], IMAGE)

    def test_worker_reports_sandbox_failure_as_job_failure(self):
        from barad import worker

        original_run = sandbox.run
        sandbox.run = lambda command, timeout=900: (2, "", "no image locally")
        try:
            with self.assertRaises(worker.WorkerError) as ctx:
                worker.run_scan(self.target, self.output, isolate_image=IMAGE)
        finally:
            sandbox.run = original_run
        self.assertIn("isolated scan failed", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()

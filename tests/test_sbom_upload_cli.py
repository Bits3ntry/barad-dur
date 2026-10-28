"""Public CLI tests: validation before any state-changing API request."""
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from threading import Thread
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts" / "sbom" / "upload.py"


class Handler(BaseHTTPRequestHandler):
    calls = []
    polls = []
    processing = False

    def do_PUT(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.calls.append((self.path, self.headers.get("X-Api-Key"), json.loads(body)))
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"token":"example-token"}')

    def do_GET(self):
        Handler.polls.append((self.path, self.headers.get("X-Api-Key")))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"processing": Handler.processing}).encode("utf-8"))

    def log_message(self, *args):
        pass


class SbomUploadTests(unittest.TestCase):
    def test_cyclonedx_17_generated_by_trivy_is_accepted(self):
        Handler.calls = []
        Handler.polls = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "bom.json"
                path.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1, "components": []}), encoding="utf-8")
                result = subprocess.run([sys.executable, str(CLI), "--file", str(path), "--project-name", "demo-service", "--project-version", "1.0.0", "--api-url", f"http://127.0.0.1:{server.server_port}"], env={**os.environ, "DT_API_KEY": "example-key"}, capture_output=True, text=True)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "upload accepted: example-token\n", ""))
                self.assertEqual(len(Handler.calls), 1)
                # Acceptance alone must not start polling: analysis stays asynchronous.
                self.assertEqual(Handler.polls, [])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_reupload_targets_same_project_and_invalid_bom_changes_nothing(self):
        Handler.calls = []
        Handler.polls = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "bom.json"
                valid = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []}
                env = {**os.environ, "DT_API_KEY": "example-key"}
                cmd = [sys.executable, str(CLI), "--file", str(path), "--project-name", "councilbox_ovac", "--project-version", "8.7.2", "--api-url", f"http://127.0.0.1:{server.server_port}"]
                path.write_text(json.dumps(valid), encoding="utf-8")
                first = subprocess.run(cmd, env=env, capture_output=True, text=True)
                second = subprocess.run(cmd, env=env, capture_output=True, text=True)
                self.assertEqual((first.returncode, first.stdout, first.stderr), (0, "upload accepted: example-token\n", ""))
                self.assertEqual((second.returncode, second.stdout, second.stderr), (0, "upload accepted: example-token\n", ""))
                self.assertEqual(len(Handler.calls), 2)
                for route, token, payload in Handler.calls:
                    self.assertEqual((route, token), ("/api/v1/bom", "example-key"))
                    self.assertEqual((payload["projectName"], payload["projectVersion"], payload["autoCreate"]), ("councilbox_ovac", "8.7.2", True))
                    self.assertEqual(json.loads(base64.b64decode(payload["bom"])), valid)
                path.write_text('{"bomFormat":"CycloneDX","specVersion":"1.6","unknown":true}', encoding="utf-8")
                rejected = subprocess.run(cmd, env=env, capture_output=True, text=True)
                self.assertEqual(rejected.returncode, 1)
                self.assertEqual(rejected.stdout, "")
                self.assertIn("invalid SBOM", rejected.stderr)
                self.assertEqual(len(Handler.calls), 2)
                path.write_text(json.dumps(valid), encoding="utf-8")
                split_identity = subprocess.run(cmd[:cmd.index("--project-name") + 1] + ["councilbox_ovac "] + cmd[cmd.index("--project-version"):], env=env, capture_output=True, text=True)
                self.assertEqual(split_identity.returncode, 1)
                self.assertEqual(split_identity.stdout, "")
                self.assertIn("invalid project identity", split_identity.stderr)
                self.assertEqual(len(Handler.calls), 2)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_wait_flag_polls_the_token_until_analysis_completes(self):
        Handler.calls = []
        Handler.polls = []
        Handler.processing = False
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "bom.json"
                path.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1, "components": []}), encoding="utf-8")
                cmd = [sys.executable, str(CLI), "--file", str(path), "--project-name", "councilbox_ovac", "--project-version", "8.7.2", "--api-url", f"http://127.0.0.1:{server.server_port}", "--wait"]
                result = subprocess.run(cmd, env={**os.environ, "DT_API_KEY": "example-key"}, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "upload accepted: example-token\nanalysis complete: example-token\n")
                self.assertEqual(result.stderr, "")
                self.assertEqual(len(Handler.calls), 1)
                self.assertEqual(Handler.polls, [("/api/v1/bom/token/example-token", "example-key")])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_wait_timeout_reports_incomplete_analysis_as_failure(self):
        Handler.calls = []
        Handler.polls = []
        Handler.processing = True
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "bom.json"
                path.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1, "components": []}), encoding="utf-8")
                cmd = [sys.executable, str(CLI), "--file", str(path), "--project-name", "councilbox_ovac", "--project-version", "8.7.2", "--api-url", f"http://127.0.0.1:{server.server_port}", "--wait", "--wait-timeout", "1"]
                result = subprocess.run(cmd, env={**os.environ, "DT_API_KEY": "example-key"}, capture_output=True, text=True)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "upload accepted: example-token\n")
                self.assertEqual(result.stderr, "analysis incomplete: no completion within 1s\n")
                self.assertGreaterEqual(len(Handler.polls), 1)
                self.assertNotIn("example-key", result.stdout + result.stderr)
        finally:
            Handler.processing = False
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    unittest.main()

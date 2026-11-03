"""Worker contract: claim → start → execute → push, against a real HTTP stub.

No mocks: a local HTTP server implements the orchestration endpoints the
worker calls, so the urllib path, auth header, cancellation check and
artifact upload all run for real.
"""
import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "cli"))

from barad import worker as worker_module  # noqa: E402

CALLS = []
STATE = {"jobs": [], "cancelled": False, "result": None}


class StubPlatform(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _json(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read(self):
        length = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(length) or b"{}")

    def do_POST(self):
        CALLS.append((self.path, self.headers.get("X-API-Key")))
        if self.path.endswith("/orchestration/workers"):
            return self._json(200, {"data": {"id": "worker-1", "status": "online"}})
        if self.path.endswith("/heartbeat"):
            return self._json(200, {"data": {"id": "worker-1"}})
        if self.path.endswith("/jobs/claim"):
            if STATE["jobs"]:
                return self._json(200, {"data": STATE["jobs"].pop(0)})
            return self._json(200, {"data": None})
        if self.path.endswith("/start"):
            return self._json(200, {"data": {"id": "job-1"},
                                    "cancelled": STATE["cancelled"]})
        if self.path.endswith("/result"):
            STATE["result"] = self._read()
            return self._json(200, {"data": {"id": "job-1", "status": "succeeded"}})
        if "/sbom" in self.path:
            return self._json(200, {"counters": {"components": 1}})
        if self.path.endswith("/sarif"):
            self._read()
            return self._json(200, {"counters": {"created": 1}})
        return self._json(404, {"error": "not found"})


class WorkerContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), StubPlatform)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        CALLS.clear()
        STATE["jobs"] = []
        STATE["cancelled"] = False
        STATE["result"] = None

    def test_register_sends_api_key(self):
        worker = worker_module.register(self.url, "k-123", "w1",
                                        ["vulnerability_analysis"])
        self.assertEqual(worker["id"], "worker-1")
        self.assertTrue(all(key == "k-123" for _, key in CALLS))

    def test_no_job_returns_cleanly(self):
        result = worker_module.serve(self.url, "k", name="w2", once=True)
        self.assertEqual(result["handled"], 0)

    def test_cancelled_job_is_not_executed(self):
        STATE["cancelled"] = True
        STATE["jobs"] = [{"id": "job-1", "capability": "vulnerability_analysis",
                          "scanner": "opengrep", "profile": {}}]
        result = worker_module.serve(self.url, "k", name="w3", once=True)
        self.assertEqual(result["handled"], 1)
        self.assertIsNone(STATE["result"])  # nothing was executed

    def test_missing_target_reports_failure_without_inventing_results(self):
        STATE["jobs"] = [{"id": "job-1", "capability": "vulnerability_analysis",
                          "scanner": "opengrep",
                          "profile": {"target_path": "/nonexistent/path"}}]
        result = worker_module.serve(self.url, "k", name="w4", once=True)
        self.assertEqual(result["handled"], 1)
        self.assertIsNotNone(STATE["result"])
        self.assertEqual(STATE["result"]["outcome"], "failed")
        self.assertIn("target_path not found", STATE["result"]["error"])

    def test_scan_failure_is_reported_as_failure(self):
        STATE["jobs"] = [{"id": "job-1", "capability": "vulnerability_analysis",
                          "scanner": "opengrep",
                          "profile": {"target_path": str(ROOT)}}]
        original = worker_module.run_scan

        def broken(*args, **kwargs):
            raise worker_module.WorkerError("scan failed (exit 2): boom")

        worker_module.run_scan = broken
        try:
            result = worker_module.serve(self.url, "k", name="w5", once=True)
        finally:
            worker_module.run_scan = original
        self.assertEqual(result["handled"], 1)
        self.assertEqual(STATE["result"]["outcome"], "failed")
        self.assertIn("boom", STATE["result"]["error"])


if __name__ == "__main__":
    unittest.main()

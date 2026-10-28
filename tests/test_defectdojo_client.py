"""Black-box tests for the reusable DefectDojo client (no MCP dependency)."""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from defectdojo_mcp.client import Client, ClientError  # noqa: E402
from defectdojo_mcp.config import Settings, SettingsError  # noqa: E402

TOKEN = "s3cr3t-token-value-abc123"


class Recorder(BaseHTTPRequestHandler):
    """Records requests and replies from a scripted queue."""

    requests = []
    responses = []

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        Recorder.requests.append({
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers),
            "body": body,
        })
        status, payload = Recorder.responses.pop(0)
        raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _handle

    def log_message(self, *args):
        pass


def settings(base_url, **overrides):
    values = {
        "DEFECTDOJO_URL": base_url,
        "DEFECTDOJO_API_TOKEN": TOKEN,
        "DEFECTDOJO_ALLOW_WRITE": "false",
        **overrides,
    }
    return Settings.from_env(values)


class ConfigTests(unittest.TestCase):
    def test_url_and_token_are_required(self):
        for missing in ("DEFECTDOJO_URL", "DEFECTDOJO_API_TOKEN"):
            values = {"DEFECTDOJO_URL": "http://127.0.0.1:18082", "DEFECTDOJO_API_TOKEN": TOKEN}
            del values[missing]
            with self.assertRaises(SettingsError) as ctx:
                Settings.from_env(values)
            self.assertIn(missing, str(ctx.exception))

    def test_remote_host_requires_explicit_override(self):
        with self.assertRaises(SettingsError) as ctx:
            Settings.from_env({"DEFECTDOJO_URL": "https://dojo.example.com",
                               "DEFECTDOJO_API_TOKEN": TOKEN})
        self.assertIn("DEFECTDOJO_ALLOW_REMOTE", str(ctx.exception))
        allowed = Settings.from_env({"DEFECTDOJO_URL": "https://dojo.example.com",
                                     "DEFECTDOJO_API_TOKEN": TOKEN,
                                     "DEFECTDOJO_ALLOW_REMOTE": "true"})
        self.assertEqual(allowed.base_url, "https://dojo.example.com")

    def test_url_with_embedded_credentials_is_rejected(self):
        with self.assertRaises(SettingsError):
            Settings.from_env({"DEFECTDOJO_URL": "http://user:pw@127.0.0.1:18082",
                               "DEFECTDOJO_API_TOKEN": TOKEN})

    def test_write_is_disabled_by_default(self):
        self.assertFalse(settings("http://127.0.0.1:18082").allow_write)

    def test_loopback_hosts_are_accepted_without_override(self):
        for host in ("127.0.0.1", "localhost"):
            self.assertTrue(settings(f"http://{host}:18082").base_url.endswith(":18082"))


class ClientReadTests(unittest.TestCase):
    def setUp(self):
        Recorder.requests = []
        Recorder.responses = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Recorder)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.client = Client(settings(self.base))

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def test_token_is_sent_as_api_key_header(self):
        Recorder.responses = [(200, {"count": 0, "results": []})]
        self.client.list_products()
        request = Recorder.requests[0]
        self.assertEqual(request["headers"]["Authorization"], f"Token {TOKEN}")
        self.assertEqual(request["path"], "/api/v2/products/?limit=100")

    def test_pagination_walks_all_pages_without_duplicates(self):
        Recorder.responses = [
            (200, {"count": 3, "next": "http://x/api/v2/findings/?limit=2&offset=2",
                   "results": [{"id": 1}, {"id": 2}]}),
            (200, {"count": 3, "next": None, "results": [{"id": 3}]}),
        ]
        found = self.client.list_all("/api/v2/findings/")
        self.assertEqual([item["id"] for item in found], [1, 2, 3])
        self.assertEqual(len(Recorder.requests), 2)
        self.assertIn("offset=2", Recorder.requests[1]["path"])

    def test_error_message_never_contains_the_token(self):
        Recorder.responses = [(403, {"detail": f"Invalid token {TOKEN}"})]
        with self.assertRaises(ClientError) as ctx:
            self.client.list_products()
        self.assertNotIn(TOKEN, str(ctx.exception))
        self.assertIn("403", str(ctx.exception))

    def test_token_is_not_leaked_when_the_host_is_unreachable(self):
        dead = Client(settings("http://127.0.0.1:1"))
        with self.assertRaises(ClientError) as ctx:
            dead.list_products()
        self.assertNotIn(TOKEN, str(ctx.exception))

    def test_read_works_while_write_is_disabled(self):
        Recorder.responses = [(200, {"count": 0, "results": []})]
        self.client.list_findings()
        self.assertEqual(Recorder.requests[0]["method"], "GET")


class ClientWriteTests(unittest.TestCase):
    def setUp(self):
        Recorder.requests = []
        Recorder.responses = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Recorder)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def test_writes_are_refused_until_explicitly_enabled(self):
        client = Client(settings(self.base))
        with self.assertRaises(ClientError) as ctx:
            client.create_finding(test=1, title="t", description="d", severity="High")
        self.assertIn("DEFECTDOJO_ALLOW_WRITE", str(ctx.exception))
        self.assertEqual(Recorder.requests, [])

    def test_create_finding_derives_required_fields(self):
        client = Client(settings(self.base, DEFECTDOJO_ALLOW_WRITE="true"))
        Recorder.responses = [
            (200, {"id": 7, "test_type": 3}),          # GET /api/v2/tests/7/
            (201, {"id": 99, "title": "SQLi"}),        # POST /api/v2/findings/
        ]
        created = client.create_finding(test=7, title="SQLi", description="proof",
                                        severity="High", active=True, verified=False)
        self.assertEqual(created["id"], 99)
        payload = json.loads(Recorder.requests[1]["body"])
        self.assertEqual(payload["numerical_severity"], "S1")
        self.assertEqual(payload["found_by"], [3])
        self.assertEqual(payload["test"], 7)
        self.assertTrue(payload["active"])
        self.assertFalse(payload["verified"])

    def test_add_note_posts_to_the_finding_notes_endpoint(self):
        client = Client(settings(self.base, DEFECTDOJO_ALLOW_WRITE="true"))
        Recorder.responses = [(201, {"id": 1, "entry": "retest pending"})]
        client.add_finding_note(99, "retest pending")
        payload = json.loads(Recorder.requests[0]["body"])
        self.assertEqual(Recorder.requests[0]["path"], "/api/v2/findings/99/notes/")
        self.assertEqual(payload["entry"], "retest pending")

    def test_import_scan_sends_multipart_with_file_and_scan_type(self):
        client = Client(settings(self.base, DEFECTDOJO_ALLOW_WRITE="true"))
        Recorder.responses = [(201, {"test": 12})]
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            handle.write('{"findings": []}')
            path = handle.name
        try:
            client.import_scan(scan_type="CycloneDX Scan", file_path=path, engagement=1)
        finally:
            os.unlink(path)
        request = Recorder.requests[0]
        self.assertEqual(request["path"], "/api/v2/import-scan/")
        self.assertIn("multipart/form-data", request["headers"]["Content-Type"])
        self.assertIn(b'name="scan_type"', request["body"])
        self.assertIn(b"CycloneDX Scan", request["body"])
        self.assertIn(b'name="file"', request["body"])


class V3ReadTests(unittest.TestCase):
    """v3 is alpha and read-only here: nested objects, no trailing slash."""

    def setUp(self):
        Recorder.requests = []
        Recorder.responses = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Recorder)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = Client(settings(f"http://127.0.0.1:{self.server.server_port}"))

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def test_collection_path_has_no_trailing_slash(self):
        Recorder.responses = [(200, {"count": 0, "next": None, "results": []})]
        self.client.v3_findings()
        self.assertEqual(Recorder.requests[0]["path"], "/api/v3/findings?limit=100")
        self.assertTrue(Recorder.requests[0]["path"].startswith("/api/v3/"))

    def test_fields_and_filters_are_forwarded(self):
        Recorder.responses = [(200, {"count": 0, "next": None, "results": []})]
        self.client.v3_findings(fields=["id", "title"], severity="High", asset=3)
        query = Recorder.requests[0]["path"].split("?", 1)[1]
        self.assertIn("fields=id%2Ctitle", query)
        self.assertIn("severity=High", query)
        self.assertIn("asset=3", query)

    def test_unsupported_filter_is_refused_before_any_request(self):
        with self.assertRaises(ClientError) as ctx:
            self.client.v3_findings(nonsense=1)
        self.assertIn("nonsense", str(ctx.exception))
        self.assertEqual(Recorder.requests, [])

    def test_missing_v3_is_reported_as_disabled_not_as_404(self):
        Recorder.responses = [(404, {"detail": "Not Found"})]
        with self.assertRaises(ClientError) as ctx:
            self.client.v3_assets()
        message = str(ctx.exception)
        self.assertIn("V3_FEATURE_LOCATIONS", message)
        self.assertNotIn("HTTP 404", message)
        self.assertNotIn(TOKEN, message)

    def test_v3_pagination_uses_the_same_envelope(self):
        Recorder.responses = [
            (200, {"count": 2, "next": "http://x/api/v3/findings?limit=1&offset=1",
                   "results": [{"id": 1}]}),
            (200, {"count": 2, "next": None, "results": [{"id": 2}]}),
        ]
        found = self.client.v3_findings(limit=1)
        self.assertEqual([f["id"] for f in found], [1, 2])
        self.assertIn("offset=1", Recorder.requests[1]["path"])

    def test_v3_never_writes_even_when_writes_are_enabled(self):
        client = Client(settings(f"http://127.0.0.1:{self.server.server_port}",
                                 DEFECTDOJO_ALLOW_WRITE="true"))
        Recorder.responses = [(200, {"id": 1})]
        client.v3_asset(1)
        self.assertEqual(Recorder.requests[0]["method"], "GET")


class V3AssetWriteTests(unittest.TestCase):
    """Assets exist only in v3, so this is the single deliberate v3 write."""

    def setUp(self):
        Recorder.requests = []
        Recorder.responses = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Recorder)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def test_asset_creation_is_refused_before_any_request_when_writes_are_off(self):
        client = Client(settings(self.base))
        with self.assertRaises(ClientError) as ctx:
            client.v3_create_asset(name="REU", description="d", organization=3)
        self.assertIn("DEFECTDOJO_ALLOW_WRITE", str(ctx.exception))
        self.assertEqual(Recorder.requests, [])

    def test_asset_creation_posts_the_required_core_fields(self):
        client = Client(settings(self.base, DEFECTDOJO_ALLOW_WRITE="true"))
        Recorder.responses = [(201, {"id": 9, "name": "REU"})]
        created = client.v3_create_asset(name="REU", description="asset", organization="3")
        self.assertEqual(created["id"], 9)
        request = Recorder.requests[0]
        self.assertEqual((request["method"], request["path"]), ("POST", "/api/v3/assets"))
        payload = json.loads(request["body"])
        self.assertEqual(payload, {"name": "REU", "description": "asset", "organization": 3})

    def test_asset_creation_rejects_a_missing_description(self):
        client = Client(settings(self.base, DEFECTDOJO_ALLOW_WRITE="true"))
        with self.assertRaises(ClientError) as ctx:
            client.v3_create_asset(name="REU", description="", organization=3)
        self.assertIn("description", str(ctx.exception))
        self.assertEqual(Recorder.requests, [])

    def test_asset_creation_rejects_unknown_fields(self):
        client = Client(settings(self.base, DEFECTDOJO_ALLOW_WRITE="true"))
        with self.assertRaises(ClientError) as ctx:
            client.v3_create_asset(name="REU", description="d", organization=3, bogus=1)
        self.assertIn("bogus", str(ctx.exception))
        self.assertEqual(Recorder.requests, [])

    def test_asset_update_patches_only_supplied_fields(self):
        client = Client(settings(self.base, DEFECTDOJO_ALLOW_WRITE="true"))
        Recorder.responses = [(200, {"id": 9, "lifecycle": "production"})]
        client.v3_update_asset(9, lifecycle="production")
        self.assertEqual(Recorder.requests[0]["method"], "PATCH")
        self.assertEqual(Recorder.requests[0]["path"], "/api/v3/assets/9")
        self.assertEqual(json.loads(Recorder.requests[0]["body"]), {"lifecycle": "production"})


if __name__ == "__main__":
    unittest.main()

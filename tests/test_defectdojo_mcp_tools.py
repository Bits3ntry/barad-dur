"""Tests for the MCP tool surface: capability gating and token hygiene."""
import asyncio
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from defectdojo_mcp.config import Settings  # noqa: E402
from defectdojo_mcp.server import build_server  # noqa: E402

TOKEN = "mcp-secret-token-xyz789"
READ_TOOLS = {
    "server_info", "list_products", "get_product", "list_engagements", "get_engagement",
    "list_tests", "get_test", "list_test_types", "list_findings", "get_finding",
    "list_assets", "get_asset", "list_organizations", "list_locations",
    "list_findings_with_context", "get_finding_with_context",
}
WRITE_TOOLS = {
    "create_finding", "update_finding", "add_finding_note", "import_scan", "reimport_scan",
    "create_asset", "update_asset", "update_product",
}
# Assets exist only in v3, so their writes are the deliberate exception.
V3_WRITE_TOOLS = {"create_asset", "update_asset"}


class Api(BaseHTTPRequestHandler):
    requests = []

    def do_GET(self):
        Api.requests.append(self.path)
        payload = {"count": 1, "next": None, "results": [
            {"id": 5, "title": "Example", "severity": "High", "active": True,
             "verified": False, "test": 3, "component_name": "left-pad"},
        ]}
        raw = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


def make_settings(base, allow_write):
    return Settings.from_env({
        "DEFECTDOJO_URL": base,
        "DEFECTDOJO_API_TOKEN": TOKEN,
        "DEFECTDOJO_ALLOW_WRITE": str(allow_write).lower(),
    })


def tool_names(server):
    return {tool.name for tool in asyncio.run(server.list_tools())}


class ToolGatingTests(unittest.TestCase):
    def test_read_only_mode_hides_every_write_tool(self):
        names = tool_names(build_server(make_settings("http://127.0.0.1:18082", False)))
        self.assertEqual(names, READ_TOOLS)
        self.assertEqual(names & WRITE_TOOLS, set())

    def test_write_mode_adds_exactly_the_write_tools(self):
        names = tool_names(build_server(make_settings("http://127.0.0.1:18082", True)))
        self.assertEqual(names, READ_TOOLS | WRITE_TOOLS)


class ToolBehaviourTests(unittest.TestCase):
    def setUp(self):
        Api.requests = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Api)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.mcp = build_server(make_settings(f"http://127.0.0.1:{self.server.server_port}", False))

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def test_server_info_never_contains_the_token(self):
        result = asyncio.run(self.mcp.call_tool("server_info", {}))
        text = json.dumps(result.model_dump(), default=str)
        self.assertNotIn(TOKEN, text)
        self.assertIn("write_enabled", text)

    def test_list_findings_returns_compact_summaries(self):
        result = asyncio.run(self.mcp.call_tool("list_findings", {"severity": "High"}))
        text = json.dumps(result.model_dump(), default=str)
        self.assertIn("left-pad", text)
        self.assertIn("severity=%s" % "High", Api.requests[0] if Api.requests else "")
        self.assertNotIn(TOKEN, text)


if __name__ == "__main__":
    unittest.main()

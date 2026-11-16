"""The MCP transport must not become a second catalog.

Two invariants:

* the tools it exposes are the catalog's rows, with the same parameters (D2);
* without a credential it says so instead of borrowing one (D44).
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend" / "src"))
sys.path.insert(0, str(ROOT / "mcp"))

from backend.app.ai import executor, tools as catalog  # noqa: E402
from barad_mcp import server as mcp_server  # noqa: E402


async def _tool_names() -> set[str]:
    listed = await mcp_server.server.list_tools()
    return {tool.name for tool in listed}


def test_tool_set_is_the_catalog_plus_the_escape_hatch():
    import asyncio
    names = asyncio.run(_tool_names())
    assert {"deployment_chain", "exposure_verdict"} <= names
    assert {"barad_tools", "barad_tool"} <= names


def test_named_tools_take_the_catalog_parameters():
    import asyncio
    listed = asyncio.run(mcp_server.server.list_tools())
    schema = {tool.name: (tool.input_schema or {}) for tool in listed}
    chain = schema["deployment_chain"].get("properties", {})
    assert set(chain) == set(catalog.BY_NAME["deployment_chain"]["params"])
    verdict = schema["exposure_verdict"].get("properties", {})
    assert set(verdict) == set(catalog.BY_NAME["exposure_verdict"]["params"])


def test_without_a_key_it_says_so_instead_of_borrowing_one(monkeypatch):
    monkeypatch.delenv("BARAD_API_KEY", raising=False)
    result = mcp_server.call("projects_list", {})
    assert result["error"] == "BARAD_API_KEY is not set"
    assert "never a shared service identity" in result["hint"]


def test_calls_go_through_the_shared_executor(monkeypatch):
    monkeypatch.setenv("BARAD_API_KEY", "k")
    monkeypatch.setenv("BARAD_URL", "http://platform:8090")
    seen = {}

    def fake_run_tool(tool, args, *, base_url, credential):
        seen.update(tool=tool, args=args, base_url=base_url, credential=credential)
        return {"tool": tool, "status": 200, "data": {}}

    monkeypatch.setattr(mcp_server.executor, "run_tool", fake_run_tool)
    mcp_server.deployment_chain(purl="pkg:npm/lodash", component=None)
    assert seen == {"tool": "deployment_chain", "args": {"purl": "pkg:npm/lodash"},
                    "base_url": "http://platform:8090", "credential": "k"}


def test_unknown_tool_name_is_an_error_not_a_silent_noop(monkeypatch):
    monkeypatch.setenv("BARAD_API_KEY", "k")

    def fake_run_tool(tool, args, *, base_url, credential):
        raise executor.ToolError(f"unknown tool: {tool}")

    monkeypatch.setattr(mcp_server.executor, "run_tool", fake_run_tool)
    result = mcp_server.barad_tool("nope", {})
    assert "unknown tool" in result["error"]
    assert "barad_tools" in result["hint"]

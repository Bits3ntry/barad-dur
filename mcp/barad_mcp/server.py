"""Barad-dûr MCP server: the same catalog, a second transport (D2, §3).

Every tool here is a thin renderer of `backend.app.ai.tools` — the catalog the
in-process executor uses. That is deliberate: an agent connecting through MCP and
the console chat cannot disagree about what a tool is called or which parameters it
takes, because there is one declaration.

The credential is the **operator's own API key**, set in their MCP client config.
The platform therefore sees exactly the identity of the human who asked, which is the
whole point of D44: an AI run never executes as a service identity.

    BARAD_URL=http://127.0.0.1:8090 BARAD_API_KEY=... python -m barad_mcp.server
"""
from __future__ import annotations

import os

from mcp.server.mcpserver import MCPServer

from backend.app.ai import executor
from backend.app.ai import tools as catalog

server = MCPServer(
    "barad-dur",
    title="Barad-dûr",
    # One declaration: the console's MCP panel prints the same text.
    instructions=catalog.MCP_INSTRUCTIONS,
    version="0.1.0",
)


def _base_url() -> str:
    return os.environ.get("BARAD_URL", "http://127.0.0.1:8090")


def _key() -> str:
    return os.environ.get("BARAD_API_KEY", "")


def call(tool: str, args: dict) -> dict:
    """The one place a tool call leaves this process."""
    key = _key()
    if not key:
        return {"error": "BARAD_API_KEY is not set",
                "hint": "the MCP server acts as you: configure your own API key in "
                        "the client, never a shared service identity"}
    return executor.run_tool(tool, {k: v for k, v in args.items() if v is not None},
                             base_url=_base_url(), credential=key)


@server.tool()
def deployment_chain(purl: str | None = None, component: str | None = None,
                     project: str | None = None, asset: str | None = None) -> dict:
    """What do we have, where is it, which version runs, how fresh is each edge.

    Facts only: no severity, no score, no `affected`. One of purl/component/project/
    asset is required.
    """
    return call("deployment_chain", {"purl": purl, "component": component,
                                     "project": project, "asset": asset})


@server.tool()
def exposure_verdict(cve: str, purl: str | None = None, depth: str = "rules") -> dict:
    """Are we involved? One vulnerability against the estate.

    Returns `affected | not_affected | unknown` per deployment, with the reasons and
    the missing edge that would settle it. `depth` is match | rules | full.
    """
    return call("exposure_verdict", {"cve": cve, "purl": purl, "depth": depth})


@server.tool()
def barad_tools() -> dict:
    """The catalog: every tool name, summary and parameter this server can call."""
    return {"tools": catalog.describe()}


@server.tool()
def barad_tool(name: str, args: dict | None = None) -> dict:
    """Call any catalog tool by name. Unknown names and unknown arguments are errors,
    never silent no-ops."""
    try:
        return call(name, args or {})
    except executor.ToolError as error:
        return {"error": str(error), "hint": "call barad_tools to see valid names"}


def main() -> None:
    transport = os.environ.get("BARAD_MCP_TRANSPORT", "stdio")
    if transport not in {"stdio", "sse", "streamable-http"}:
        transport = "stdio"
    server.run(transport=transport)  # type: ignore[arg-type]


if __name__ == "__main__":
    main()

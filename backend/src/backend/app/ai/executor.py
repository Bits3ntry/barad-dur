"""Execute a catalog entry as the *run's* principal (D2, D44).

Two things this module refuses to do, both on purpose:

* **It never falls back to a service key.** The caller passes the credential of the
  human (or API key) that started the run. An assistant that silently runs with a
  longer-lived credential is a privilege-escalation path, and `auth.py` says API keys
  bypass RBAC by design — so the executor must be handed *who is asking*.
* **It never parses a tool's output into an opinion.** It returns the payload, and
  `compact()` only shortens it. Interpretation belongs to the specialists.

A tool error is data, not an exception the specialist can ignore: `{"error": ...,
"hint": ...}`. An agent that read exceptions as "no results" would report a clean
estate every time the platform hiccupped.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

from backend.app.ai import tools as catalog

MAX_STRING = 2000
MAX_LIST = 50
MAX_PAYLOAD_BYTES = 24000


class ToolError(RuntimeError):
    """Raised only for a programming error (unknown tool, missing path param)."""


def _bind(tool: dict, args: dict) -> tuple[str, dict, dict]:
    """Split args into path substitutions and query params, dropping empty ones.

    An argument the tool does not declare is an **error**, not a no-op: a model that
    sends `version` to a tool without it must be told, not silently answered from a
    different question.
    """
    path = tool["path"]
    unknown = set(args) - set(tool["params"])
    if unknown:
        raise ToolError(f"{tool['name']} does not accept {sorted(unknown)}")
    query: dict[str, Any] = {}
    for name, spec in tool["params"].items():
        value = args.get(name)
        if value is None or value == "":
            if spec.get("required") and spec["in"] == "path":
                raise ToolError(f"{tool['name']} requires {name}")
            continue
        if spec["in"] == "path":
            path = path.replace("{" + name + "}", str(value))
        else:
            query[name] = value
    if "{" in path:
        raise ToolError(f"{tool['name']} is missing a path parameter")
    return path, query, args


def build_request(tool_name: str, args: dict) -> tuple[str, str, dict]:
    tool = catalog.BY_NAME.get(tool_name)
    if tool is None:
        raise ToolError(f"unknown tool: {tool_name}")
    path, query, _ = _bind(tool, args)
    return tool["method"], path, query


def compact(payload: Any, max_string: int = MAX_STRING,
            max_list: int = MAX_LIST) -> Any:
    """Shorten a payload without changing its shape (D13).

    Long strings keep their head and say so; long lists keep their first entries and
    a count. A model that receives the truncation marker knows the answer is partial
    — which is the only thing that makes trimming safe.
    """
    if isinstance(payload, dict):
        return {key: compact(value, max_string, max_list)
                for key, value in payload.items()}
    if isinstance(payload, list):
        trimmed = [compact(value, max_string, max_list)
                   for value in payload[:max_list]]
        if len(payload) > max_list:
            trimmed.append({"_truncated": len(payload) - max_list})
        return trimmed
    if isinstance(payload, str) and len(payload) > max_string:
        return payload[:max_string] + f"…[+{len(payload) - max_string} chars]"
    return payload


def run_tool(tool_name: str, args: dict, *, base_url: str,
             credential: str | None = None, header: str = "X-API-Key",
             client: httpx.Client | None = None) -> dict:
    """Call the platform as `credential` and return `{tool, status, data|error}`."""
    if not credential:
        raise ToolError("no credential: an AI run executes as its caller, never as "
                        "a service identity (D44)")
    method, path, query = build_request(tool_name, args)
    url = base_url.rstrip("/") + path
    owns_client = client is None
    if owns_client:
        client = httpx.Client(timeout=30.0)
    try:
        response = client.request(method, url, params=query,
                                  headers={header: credential})
    except httpx.HTTPError as error:  # a transport failure must name its target
        return {"tool": tool_name, "status": 0,
                "error": f"platform unreachable at {url}: {error}"}
    finally:
        if owns_client:
            client.close()

    if response.status_code >= 400:
        hint = "the platform answered an error, not an empty set — never read this " \
               "as 'nothing found'"
        try:
            body = response.json()
        except ValueError:
            body = response.text[:500]
        return {"tool": tool_name, "status": response.status_code,
                "error": body, "hint": hint}

    try:
        data = response.json()
    except ValueError:
        return {"tool": tool_name, "status": response.status_code,
                "error": "platform returned non-JSON", "hint": "treat as unknown"}
    payload = compact(data)
    size = len(json.dumps(payload))
    return {"tool": tool_name, "status": response.status_code, "data": payload,
            "bytes": size, "truncated": size >= MAX_PAYLOAD_BYTES}

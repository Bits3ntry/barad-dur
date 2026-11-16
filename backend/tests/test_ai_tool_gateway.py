"""The tool gateway: one catalog, and an executor that refuses a service identity.

The two properties under test are the ones that keep an agent honest:

* `executor.run_tool` **requires the caller's credential** (D44). There is no env
  fallback, because a fallback is a silent privilege escalation.
* a tool error is returned as data, with a hint that says it is not an empty set —
  so no specialist can read "platform hiccup" as "the estate is clean".
"""
import json
import sys
from pathlib import Path

import httpx
import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app.ai import executor, tools  # noqa: E402


def test_every_catalog_path_exists_in_the_application(monkeypatch, tmp_path):
    """The catalog cannot drift from the API.

    This is the test that would have caught a second `/api/v1/components` being
    written next to the one `inventory.py` already served: FastAPI keeps the first
    route registered, so a duplicate is dead code that answers the wrong shape.
    """
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/routes.db")
    from backend.app.main import create_app

    app = create_app()
    # `app.routes` holds `_IncludedRouter` objects in this FastAPI version, so the
    # flattened surface is the OpenAPI document — which is also what a client sees.
    paths = set(app.openapi()["paths"])
    missing = [(tool["name"], tool["path"]) for tool in tools.TOOLS
               if tool["path"] not in paths]
    assert not missing, f"catalog points at routes that do not exist: {missing}"


def test_every_read_tool_is_dispatched():
    """A tool in the list that cannot be dispatched is a lie (D2)."""
    from backend.app.ai import dispatch

    missing = [tool["name"] for tool in tools.TOOLS
               if tool["method"] == "GET" and tool["name"] not in dispatch.dispatched()]
    assert not missing, f"catalog tools with no in-process handler: {missing}"
    extra = [name for name in dispatch.dispatched() if name not in tools.BY_NAME]
    assert not extra, f"dispatched names that are not in the catalog: {extra}"


def test_catalog_exposes_the_two_composites_first():
    names = [tool["name"] for tool in tools.TOOLS]
    assert names[:2] == ["deployment_chain", "exposure_verdict"]
    described = tools.describe()
    assert {row["name"] for row in described} == set(names)
    # Every declared param points at a real endpoint, and path params are required.
    for tool in tools.TOOLS:
        for name, spec in tool["params"].items():
            if spec["in"] == "path":
                assert spec.get("required") is True, f"{tool['name']}.{name}"
                assert "{" + name + "}" in tool["path"]


def test_build_request_splits_path_and_query():
    method, path, query = executor.build_request(
        "intel_kev", {"cve_id": "CVE-2021-23337"})
    assert method == "GET"
    assert path == "/api/v1/intel/kev/CVE-2021-23337"
    assert query == {}

    _, path, query = executor.build_request(
        "exposure_verdict", {"cve": "CVE-2021-23337", "depth": None})
    assert path == "/api/v1/exposure/verdict"
    assert query == {"cve": "CVE-2021-23337"}, "empty values must not be sent"


def test_unknown_tool_and_missing_path_param_are_programming_errors():
    with pytest.raises(executor.ToolError):
        executor.build_request("nope", {})
    with pytest.raises(executor.ToolError):
        executor.build_request("deployment_chain",
                               {"purl": "pkg:npm/x", "ref": "y"})


def test_executor_refuses_to_run_without_a_caller_credential():
    with pytest.raises(executor.ToolError, match="never as a service identity"):
        executor.run_tool("projects_list", {}, base_url="http://platform:8090")


def test_executor_returns_payload_and_trims_it():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["X-API-Key"] == "k"
        return httpx.Response(200, json={"data": {"rows": [{"n": i} for i in range(80)],
                                                  "note": "x" * 5000}})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = executor.run_tool("projects_list", {}, base_url="http://platform:8090",
                               credential="k", client=client)
    assert result["status"] == 200
    rows = result["data"]["data"]["rows"]
    assert len(rows) == 51                      # 50 kept + the truncation marker
    assert rows[-1] == {"_truncated": 30}
    assert "chars]" in result["data"]["data"]["note"]


def test_a_tool_error_is_data_and_says_it_is_not_an_empty_set():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"detail": "no component"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = executor.run_tool("deployment_chain", {"purl": "pkg:npm/x"},
                               base_url="http://platform:8090", credential="k",
                               client=client)
    assert result["status"] == 404
    assert result["error"] == {"detail": "no component"}
    assert "never read this as 'nothing found'" in result["hint"]


def test_transport_failure_names_the_endpoint():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = executor.run_tool("projects_list", {}, base_url="http://platform:8090",
                               credential="k", client=client)
    assert result["status"] == 0
    assert "http://platform:8090/api/v1/projects" in result["error"]


def test_no_query_object_reaches_an_in_process_handler():
    """A route default written `Query(...)` is an object, not a value.

    FastAPI resolves it at request time; this dispatcher calls the function directly.
    Passing the object through reached SQLAlchemy as a bind parameter and made
    `findings_search`, `vulnerabilities_search` and `assets_search` fail with
    `cannot adapt type 'Query'` — a dead tool the model read as an empty estate.
    """
    import inspect

    from fastapi.params import Query

    from backend.app.ai import dispatch

    for name in dispatch.dispatched():
        handler = dispatch._DISPATCH[name]
        names, defaults = dispatch._call_plan(handler)
        assert not any(isinstance(value, Query) for value in defaults.values()), name
        # Every declared catalog param resolves to a kwarg the function accepts.
        signature = inspect.signature(handler).parameters
        for declared in tools.BY_NAME[name]["params"]:
            assert names.get(declared), f"{name}.{declared} has no handler kwarg"
            assert names[declared] in signature, f"{name}.{declared} maps to a ghost"


def test_every_list_tool_answers_in_process_over_an_empty_estate(tmp_path, monkeypatch):
    """All three list tools must return a page, not an exception, with zero rows."""
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/dispatch.db")
    monkeypatch.setenv("BOOTSTRAP_TOKEN", "boot")
    from backend.app import models
    from backend.app.ai import dispatch
    from backend.app.db import session_factory
    from backend.app.main import create_app

    create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.commit()

    for name in ("findings_search", "vulnerabilities_search", "assets_search"):
        payload = dispatch.call(name, {}, org=org, session=session)
        assert payload["total"] == 0, name
        assert payload["data"] == [], name
        session.rollback()
    session.close()


def test_a_tool_projection_keeps_the_totals_and_samples_the_rows():
    """`total` must survive a 200-row page, or the model answers "no reliable total".

    The console payloads are shaped for screens; dropping them into the prompt as one
    `json.dumps(...)[:12000]` put 200 findings rows before `total` and cut the number
    off — over a query that had just succeeded.
    """
    from backend.app.ai.state import MAX_TOOL_CHARS, projection

    rows = [{"id": f"f-{index}", "title": "x" * 300, "severity": "HIGH"}
            for index in range(200)]
    text = projection({"data": rows, "total": 1284, "limit": 200, "offset": 0})

    assert len(text) <= MAX_TOOL_CHARS
    assert text.index('"total"') < text.index('"data"'), "the numbers come first"
    payload = json.loads(text)          # valid JSON, not a string sliced mid-object
    assert payload["total"] == 1284
    assert len(payload["data"]) <= 13   # a sample plus the hidden-count marker
    assert payload["data"][-1]["_rows_hidden"] == 200 - (len(payload["data"]) - 1)




def test_every_tool_the_planner_names_exists_in_the_catalogue():
    """A planner tool that is not in the catalogue is silently dropped at call time, and
    the plan is written from whatever the model remembers — the exact failure mode this
    guards."""
    from backend.app.ai import planner, tools as catalog

    missing = [name for name in planner.PLANNER_TOOLS if name not in catalog.BY_NAME]
    assert missing == [], f"planner names tools the catalogue cannot serve: {missing}"
    assert "finding_trace" in planner.PLANNER_TOOLS, \
        "a plan that ignores what was already tried repeats a failed attempt"

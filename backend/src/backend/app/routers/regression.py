"""BL-080: regression tests — definitions, authorized replay, redaction.

Invariants pinned here:
  - Every execution goes through `authorize()` (capability
    `active_verification`); no grant → 403 and nothing is sent.
  - Methods that mutate state (POST/PUT/PATCH/DELETE) additionally require
    `intrusive_testing` authorization — a GET grant never implies them.
  - Evidence is redacted: secret-bearing headers and credential-looking
    strings never reach storage or the API.
  - `reintroduced` is only set when a check that previously passed now fails.
"""
import json
import urllib.error
import urllib.request

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from backend.app import auth, authorization, models, redaction
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1/regression", tags=["regression"])

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
MAX_BODY = 4096

_redact_headers = redaction.redact_headers
_scrub = redaction.redact_text


def _test_data(row: models.RegressionTest) -> dict:
    return {"id": row.id, "name": row.name, "suite": row.suite,
            "method": row.method, "url": row.url,
            "headers": _redact_headers(json.loads(row.headers or "{}")),
            "assertions": json.loads(row.assertions or "[]"),
            "expected_outcome": row.expected_outcome,
            "project_id": row.project_id,
            "project_version_id": row.project_version_id,
            "source_finding_id": row.source_finding_id}


def _run_data(row: models.RegressionRun) -> dict:
    return {"id": row.id, "test_id": row.test_id, "result": row.result,
            "http_status": row.http_status, "latency_ms": row.latency_ms,
            "reintroduced": row.reintroduced,
            "error": row.error, "actor": row.actor,
            "ran_at": row.ran_at.isoformat(),
            "evidence": json.loads(row.evidence) if row.evidence else None}


class Assertion(BaseModel):
    type: str
    value: str | int | None = None
    name: str | None = None

    @field_validator("type")
    @classmethod
    def known(cls, value):
        allowed = {"status_equals", "status_not_equals", "body_contains",
                   "body_not_contains", "header_equals", "header_absent"}
        if value not in allowed:
            raise ValueError(f"assertion type must be one of {sorted(allowed)}")
        return value


class TestIn(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    url: str = Field(min_length=8, max_length=2048)
    method: str = "GET"
    headers: dict[str, str] = {}
    body: str | None = None
    assertions: list[Assertion] = []
    suite: str = "default"
    project: str | None = None
    version: str | None = None
    source_finding_id: str | None = None
    actor: str = Field(min_length=2, max_length=255)

    @field_validator("method")
    @classmethod
    def method_known(cls, value):
        upper = value.upper()
        if upper not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError("unsupported HTTP method")
        return upper

    @field_validator("url")
    @classmethod
    def http_only(cls, value):
        if not value.lower().startswith(("http://", "https://")):
            raise ValueError("url must be http(s)")
        return value


@router.post("/tests")
def create_test(payload: TestIn = None,
                org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    project_id = None
    pv_id = None
    if payload.project:
        project = (session.query(models.Project)
                   .filter_by(org_id=org.id, slug=payload.project).one_or_none())
        if project is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
        project_id = project.id
        if payload.version:
            pv = (session.query(models.ProjectVersion)
                  .filter_by(project_id=project.id, version=payload.version)
                  .one_or_none())
            if pv is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "version not found")
            pv_id = pv.id
    if payload.source_finding_id:
        finding = session.get(models.PentestFinding, payload.source_finding_id)
        if finding is None or finding.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "pentest finding not found")
    now = models.utcnow()
    row = models.RegressionTest(
        org_id=org.id, project_id=project_id, project_version_id=pv_id,
        suite=payload.suite, name=payload.name, method=payload.method,
        url=payload.url, headers=json.dumps(payload.headers),
        body=payload.body,
        assertions=json.dumps([a.model_dump() for a in payload.assertions]),
        source_finding_id=payload.source_finding_id,
        created_at=now, updated_at=now)
    session.add(row)
    session.flush()
    _audit_log(session, org.id, payload.actor, "regression.test_created",
               "regression_test", row.id, payload.name)
    session.commit()
    return {"data": _test_data(row)}


@router.get("/tests")
def list_tests(suite: str | None = None,
               org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    query = session.query(models.RegressionTest).filter_by(org_id=org.id)
    if suite:
        query = query.filter_by(suite=suite)
    rows = query.order_by(models.RegressionTest.created_at).all()
    data = []
    for row in rows:
        last = (session.query(models.RegressionRun)
                .filter_by(test_id=row.id)
                .order_by(models.RegressionRun.ran_at.desc()).first())
        data.append({**_test_data(row),
                     "last_run": _run_data(last) if last else None})
    return {"data": data, "total": len(rows)}


@router.get("/tests/{test_id}/runs")
def list_runs(test_id: str,
              org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session)):
    row = session.get(models.RegressionTest, test_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "test not found")
    runs = (session.query(models.RegressionRun)
            .filter_by(test_id=row.id)
            .order_by(models.RegressionRun.ran_at.desc()).all())
    return {"data": [_run_data(r) for r in runs], "total": len(runs)}


def _evaluate(assertions: list[dict], http_status: int, body: str,
              headers: dict) -> list[dict]:
    results = []
    lowered = {k.lower(): v for k, v in headers.items()}
    for item in assertions:
        kind = item.get("type")
        value = item.get("value")
        name = (item.get("name") or "").lower()
        if kind == "status_equals":
            ok = http_status == int(value)
            detail = f"status {http_status} == {value}"
        elif kind == "status_not_equals":
            ok = http_status != int(value)
            detail = f"status {http_status} != {value}"
        elif kind == "body_contains":
            ok = str(value) in body
            detail = f"body contains {value!r}"
        elif kind == "body_not_contains":
            ok = str(value) not in body
            detail = f"body lacks {value!r}"
        elif kind == "header_equals":
            ok = lowered.get(name) == str(value)
            detail = f"header {name} == {value!r}"
        elif kind == "header_absent":
            ok = name not in lowered
            detail = f"header {name} absent"
        else:
            ok = False
            detail = f"unsupported assertion {kind}"
        results.append({"assertion": item, "ok": ok, "detail": detail})
    return results


class RunIn(BaseModel):
    actor: str = Field(min_length=2, max_length=255)
    principal: str | None = None
    environment: str | None = None
    authorization_grant: str | None = None


@router.post("/tests/{test_id}/run")
def run_test(test_id: str, payload: RunIn = None,
             org: models.Organization = Depends(auth.require_org),
             session: Session = Depends(get_session)):
    """Replay the check — only if the org holds an active grant covering it."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    row = session.get(models.RegressionTest, test_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "test not found")

    principal = payload.principal or payload.actor
    targets = [{"type": "url", "value": row.url}]
    decision = authorization.authorize(
        session, org.id, principal, "active_verification", targets,
        tool="regression", environment=payload.environment)
    if decision["decision"] == "deny":
        _audit_log(session, org.id, payload.actor, "regression.denied",
                   "regression_test", row.id, decision["reason"][:300])
        session.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            f"not authorized: {decision['reason']}")
    if row.method not in SAFE_METHODS:
        intrusive = authorization.authorize(
            session, org.id, principal, "intrusive_testing", targets,
            tool="regression", environment=payload.environment)
        if intrusive["decision"] == "deny":
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"{row.method} requires intrusive_testing authorization: "
                f"{intrusive['reason']}")

    request_headers = json.loads(row.headers or "{}")
    request = urllib.request.Request(
        row.url, method=row.method,
        data=row.body.encode() if row.body else None,
        headers=request_headers)
    started = models.utcnow()
    http_status = None
    response_headers = {}
    body_text = ""
    error = None
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            http_status = response.status
            response_headers = dict(response.headers)
            body_text = response.read(MAX_BODY).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        http_status = exc.code
        response_headers = dict(exc.headers or {})
        body_text = exc.read(MAX_BODY).decode("utf-8", "replace")
    except Exception as exc:  # network failures are results, not crashes
        error = f"{type(exc).__name__}: {exc}"[:400]
    latency = int((models.utcnow() - started).total_seconds() * 1000)

    results = _evaluate(json.loads(row.assertions or "[]"), http_status or 0,
                        body_text, response_headers) if error is None else []
    if error is not None:
        result = "error"
    elif results and all(item["ok"] for item in results):
        result = "passed"
    elif not results:
        result = "passed" if (http_status or 0) < 400 else "failed"
    else:
        result = "failed"

    previous = (session.query(models.RegressionRun)
                .filter_by(test_id=row.id)
                .order_by(models.RegressionRun.ran_at.desc()).first())
    reintroduced = bool(previous and previous.result == "passed" and result == "failed")

    evidence = {
        "request": {"method": row.method, "url": _scrub(row.url),
                    "headers": _redact_headers(request_headers)},
        "response": {"status": http_status,
                     "headers": _redact_headers(response_headers),
                     "body": _scrub(body_text)[:MAX_BODY]},
        "assertions": results,
    }
    run = models.RegressionRun(
        org_id=org.id, test_id=row.id,
        project_version_id=row.project_version_id, result=result,
        http_status=http_status, latency_ms=latency, reintroduced=reintroduced,
        evidence=json.dumps(evidence), error=error, actor=payload.actor,
        ran_at=models.utcnow())
    session.add(run)
    session.flush()
    _audit_log(session, org.id, payload.actor, "regression.run",
               "regression_test", row.id,
               f"{result}{' (reintroduced)' if reintroduced else ''}")
    session.commit()
    return {"data": _run_data(run), "reintroduced": reintroduced}


@router.get("/suites")
def suites(org: models.Organization = Depends(auth.require_org),
           session: Session = Depends(get_session)):
    rows = (session.query(models.RegressionTest.suite)
            .filter_by(org_id=org.id).distinct().all())
    return {"data": sorted({r[0] for r in rows})}

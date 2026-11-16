"""Repeat: re-send what a finding claims, with the login it needs to be reachable.

A row that says *"POST /rest/user/login with this payload"* is not reproducible on
its own when the endpoint sits behind a session: the token has to come from
somewhere. Burp's Repeater leaves that to a person copy-pasting headers between
tabs; this executes a **chain** instead — an ordered list of steps where a later
step may reference what an earlier one extracted:

    step 1  POST /rest/user/login          → extract authentication.token  as `token`
    step 2  GET  /api/Users/1              Authorization: Bearer {{token}}

Rules that make a chain trustworthy:

* **Every step goes through `authorize()`** — `active_verification`, plus
  `intrusive_testing` for anything that is not a safe method. A chain is a scan;
  it does not get a pass for being typed by hand.
* **The request is echoed as it was written, not as it was sent.** Values injected
  from a previous step stay as `{{token}}` in the stored request and the resolved
  value is reported once, in `variables`. That is what makes the record readable
  (and shareable) without turning the row into a credential store.
* **An extraction that finds nothing stops the chain.** A second step that runs
  with an unsubstituted `{{token}}` produces a 401 nobody can explain; the honest
  answer is "step 1 returned no token".
* **A failure is a result, not an exception.** Denied, timed out, 500 — each step
  reports its own outcome and the chain stops where it stopped.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request

from backend.app import authorization, models, redaction

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
TIMEOUT = 10.0
READ_LIMIT = 65536      # bytes read from the wire
STORE_LIMIT = 8192      # bytes of body kept as evidence
PLACEHOLDER = re.compile(r"\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}")
METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}


class ChainError(Exception):
    """The chain cannot run as written: nothing was sent."""


def _substitute(value: str | None, variables: dict) -> str | None:
    """Fill `{{name}}` from what earlier steps extracted."""
    if value is None:
        return None
    return PLACEHOLDER.sub(lambda match: str(variables.get(match.group(1), match.group(0))),
                           value)


def _missing(value: str | None, variables: dict) -> list[str]:
    if not value:
        return []
    return [name for name in PLACEHOLDER.findall(value) if name not in variables]


def _json_path(payload, path: str):
    """`authentication.token` / `data.0.id` — dot path, no JSONPath dialect."""
    current = payload
    for part in (path or "").split("."):
        if part == "":
            continue
        if isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(current, dict):
            current = current.get(part)
        else:
            return None
        if current is None:
            return None
    return current


def extract(payload: dict, rules: list[dict], variables: dict) -> tuple[dict, list[dict]]:
    """Apply the extraction rules of one step. `({name: value}, [report])`."""
    found: dict = {}
    report: list[dict] = []
    body = payload.get("body") or ""
    headers = {str(key).lower(): str(value)
               for key, value in (payload.get("response_headers") or {}).items()}
    for rule in rules or []:
        name = (rule.get("var") or "").strip()
        if not name:
            continue
        kind = (rule.get("from") or "json").lower()
        value = None
        if kind == "json":
            try:
                value = _json_path(json.loads(body), rule.get("path") or "")
            except ValueError:
                value = None
        elif kind == "regex":
            try:
                match = re.search(rule.get("path") or "", body)
                value = match.group(1) if match and match.groups() else (
                    match.group(0) if match else None)
            except re.error:
                value = None
        elif kind == "header":
            value = headers.get((rule.get("path") or "").lower())
        if value is None or value == "":
            report.append({"var": name, "from": kind, "ok": False,
                           "detail": f"no value at {rule.get('path')!r}"})
            continue
        variables[name] = value
        found[name] = value
        report.append({"var": name, "from": kind, "ok": True,
                       "detail": f"{len(str(value))} chars"})
    return found, report


def _echoed_headers(raw: dict) -> dict:
    """The request as it was written, for the record.

    A secret header whose value is a placeholder holds no secret — it is the one
    thing a reader needs to see to understand the chain ("step 2 authenticated with
    `Bearer {{token}}`"). Anything carrying a real literal is redacted as usual, and
    the substituted values never reach this function: the record is what a person
    typed, the wire got the rest.
    """
    out = {}
    for key, value in (raw or {}).items():
        secret = str(key).lower() in redaction.SECRET_HEADERS
        out[key] = "[REDACTED]" if secret and "{{" not in str(value) else value
    return out


def _send(method: str, url: str, headers: dict, body: str | None):
    """One HTTP exchange. Network failures are values, never exceptions."""
    request = urllib.request.Request(
        url, method=method, headers={str(k): str(v) for k, v in (headers or {}).items()},
        data=body.encode() if body not in (None, "") else None)
    started = models.utcnow()
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            status_code = response.status
            response_headers = dict(response.headers)
            text = response.read(READ_LIMIT).decode("utf-8", "replace")
        error = None
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        response_headers = dict(exc.headers or {})
        text = exc.read(READ_LIMIT).decode("utf-8", "replace")
        error = None
    except Exception as exc:  # noqa: BLE001 — a refused connection is an outcome
        status_code = None
        response_headers = {}
        text = ""
        error = f"{type(exc).__name__}: {exc}"[:400]
    latency = int((models.utcnow() - started).total_seconds() * 1000)
    return status_code, response_headers, text, error, latency


def run(session, org, steps: list[dict], actor: str = "console",
        principal: str | None = None, environment: str | None = None) -> dict:
    """Execute the chain. Returns the whole story, step by step."""
    if not steps:
        raise ChainError("a chain needs at least one step")
    who = principal or actor or "console"
    variables: dict = {}
    executed: list[dict] = []

    for index, raw in enumerate(steps, start=1):
        method = str(raw.get("method") or "GET").upper()
        if method not in METHODS:
            raise ChainError(f"step {index}: unsupported method {method!r}")
        url = _substitute(raw.get("url"), variables)
        if not url or not str(url).lower().startswith(("http://", "https://")):
            raise ChainError(f"step {index}: url must be http(s)")
        raw_headers = {str(key): str(value)
                       for key, value in (raw.get("headers") or {}).items()}
        raw_body = raw.get("body")
        headers = {key: _substitute(value, variables)
                   for key, value in raw_headers.items()}
        body = _substitute(raw_body, variables)
        label = (raw.get("label") or f"step {index}")[:120]

        # An unsubstituted placeholder means an earlier step did not produce it.
        for text in (url, body, " ".join(str(v) for v in headers.values())):
            gaps = _missing(text, variables)
            if gaps:
                executed.append({
                    "index": index, "label": label, "method": method,
                    "url": redaction.redact_text(str(url)), "status": None,
                    "authorized": True,
                    "error": f"missing variable(s): {', '.join(sorted(gaps))}",
                    "request_headers": _echoed_headers(raw_headers),
                    "request_body": raw_body, "response_headers": {}, "response_body": "",
                    "latency_ms": None, "extracted": {},
                })
                return {"result": "error", "steps": executed, "variables": variables,
                        "error": f"step {index}: unresolved placeholder"}

        decision = authorization.authorize(
            session, org.id, who, "active_verification",
            [{"type": "url", "value": url}], tool="repeat", environment=environment)
        if decision["decision"] == "deny":
            executed.append({
                "index": index, "label": label, "method": method,
                "url": redaction.redact_text(str(url)), "status": None,
                "authorized": False, "error": decision["reason"][:300],
                "request_headers": _echoed_headers(raw_headers),
                "request_body": raw_body, "response_headers": {}, "response_body": "",
                "latency_ms": None, "extracted": {},
            })
            return {"result": "denied", "steps": executed, "variables": variables,
                    "error": f"step {index}: not authorized"}
        if method not in SAFE_METHODS:
            intrusive = authorization.authorize(
                session, org.id, who, "intrusive_testing",
                [{"type": "url", "value": url}], tool="repeat", environment=environment)
            if intrusive["decision"] == "deny":
                executed.append({
                    "index": index, "label": label, "method": method,
                    "url": redaction.redact_text(str(url)), "status": None,
                    "authorized": False,
                    "error": f"{method} needs intrusive_testing: {intrusive['reason'][:260]}",
                    "request_headers": _echoed_headers(raw_headers),
                    "request_body": raw_body, "response_headers": {}, "response_body": "",
                    "latency_ms": None, "extracted": {},
                })
                return {"result": "denied", "steps": executed, "variables": variables,
                        "error": f"step {index}: intrusive_testing not granted"}

        status_code, response_headers, text, error, latency = _send(
            method, str(url), headers, body)
        found, report = extract(
            {"body": text, "response_headers": response_headers},
            raw.get("extract") or [], variables)
        executed.append({
            "index": index, "label": label, "method": method,
            "url": redaction.redact_text(str(url)),
            "status": status_code, "authorized": True, "error": error,
            "request_headers": _echoed_headers(raw_headers),
            "request_body": raw_body,
            "response_headers": redaction.redact_headers(response_headers),
            "response_body": redaction.redact_text(text[:STORE_LIMIT]),
            "truncated": len(text) > STORE_LIMIT,
            "latency_ms": latency,
            "extracted": {name: {"chars": len(str(value))} for name, value in found.items()},
            "extractions": report,
        })
        if error is not None:
            return {"result": "error", "steps": executed, "variables": variables,
                    "error": f"step {index}: {error}"}
        failed = [item for item in report if not item["ok"]]
        if failed:
            return {"result": "error", "steps": executed, "variables": variables,
                    "error": f"step {index}: no {failed[0]['var']} in the response"}

    return {"result": "ok", "steps": executed, "variables": variables, "error": None}


def chain_from_finding(session, finding: models.Finding) -> list[dict]:
    """A starting chain for a finding: its login profile, then its own request.

    Seeded, never guessed: the profile's steps are used verbatim, and the finding
    contributes only what it states (method, where, the proof body). A chain that
    invents a URL to reach a finding nobody could reach is worse than no chain.
    """
    steps: list[dict] = []
    # An agent finding carries the exact request that proved it on its candidate —
    # method, headers and body included. Re-sending the bare URL as a GET would
    # "validate" nothing, so that request is the chain whenever it exists.
    if getattr(finding, "agent_candidate_id", None):
        candidate = session.get(models.Candidate, finding.agent_candidate_id)
        if candidate is not None:
            try:
                envelope = json.loads(candidate.evidence or "{}")
            except ValueError:
                envelope = {}
            request = (envelope.get("request")
                       if isinstance(envelope, dict) else None)
            if isinstance(request, dict) and request.get("url"):
                return [{**request,
                         "label": request.get("label")
                         or "the request that proved it"}]
    profile = (session.get(models.AuthProfile, finding.auth_profile_id)
               if finding.auth_profile_id else None)
    if profile is not None:
        try:
            seeded = json.loads(profile.login_steps or "[]")
        except ValueError:
            seeded = []
        if isinstance(seeded, dict):
            seeded = [seeded]
        for item in seeded or []:
            if isinstance(item, dict):
                steps.append({**item, "label": item.get("label") or "login"})
    target = finding.url or ""
    if finding.endpoint:
        # The endpoint is the path; the url may carry a client-side route that is
        # not where the request goes.
        base = target.split("#")[0].rstrip("/")
        if base:
            target = base + (finding.endpoint if finding.endpoint.startswith("/")
                             else "/" + finding.endpoint)
    if target:
        headers = {}
        if profile is not None and profile.headers:
            try:
                parsed = json.loads(profile.headers)
                if isinstance(parsed, dict):
                    headers = {str(k): str(v) for k, v in parsed.items()}
            except ValueError:
                headers = {}
        steps.append({
            "label": "the request the finding claims",
            "method": (finding.http_method or "GET").upper(),
            "url": target, "headers": headers, "body": None,
        })
    return steps

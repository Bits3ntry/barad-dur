"""Minimal Jira REST client (stdlib only) for the BL-050 bridge.

Credentials come from the organization's saved Jira connection
(`app/integrations.py`) when one exists; the environment is the fallback for
deployments configured the old way:

  JIRA_BASE_URL   e.g. https://company.atlassian.net
  JIRA_EMAIL      account email for basic auth
  JIRA_TOKEN      API token (never logged, never returned to clients)

The bridge is deliberately narrow: it creates/updates the issues Barad-dûr
asks for and reads their status/assignee back. It never touches finding
state — Jira is the source of truth only for its own task workflow.
"""
import base64
import json
import os
import urllib.error
import urllib.request


class JiraError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


def config_for(session=None, org_id: str | None = None) -> tuple[str, str, str]:
    """(base_url, email, token): saved connection first, environment second."""
    if session is not None and org_id:
        from backend.app import integrations

        saved = integrations.for_tickets(session, org_id)
        if saved is not None and saved.get("token"):
            return (saved.get("base_url") or "").rstrip("/"), \
                saved.get("account") or "", saved["token"]
    base = (os.environ.get("JIRA_BASE_URL") or "").rstrip("/")
    email = os.environ.get("JIRA_EMAIL") or ""
    token = os.environ.get("JIRA_TOKEN") or ""
    if not base or not token:
        raise JiraError("jira_not_configured")
    return base, email, token


def _config(config: tuple[str, str, str] | None = None) -> tuple[str, str, str]:
    if config is not None:
        base, email, token = config
        if not base or not token:
            raise JiraError("jira_not_configured")
        return base.rstrip("/"), email, token
    return config_for()


def configured(session=None, org_id: str | None = None) -> bool:
    try:
        config_for(session, org_id)
        return True
    except JiraError:
        return False


def request(method: str, path: str, payload: dict | None = None,
            timeout: float = 10.0,
            config: tuple[str, str, str] | None = None) -> dict:
    base, email, token = _config(config)
    url = f"{base}/rest/api/3{path}"
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    credential = base64.b64encode(f"{email}:{token}".encode()).decode()
    req.add_header("Authorization", f"Basic {credential}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read().decode() or "{}"
            return json.loads(body)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode()[:400]
        raise JiraError(f"jira_http_{exc.code}: {detail}", exc.code) from exc
    except urllib.error.URLError as exc:
        raise JiraError(f"jira_unreachable: {exc.reason}") from exc


def adf_paragraphs(text: str) -> dict:
    """Jira Cloud expects Atlassian Document Format for descriptions."""
    blocks = []
    for line in (text or "").splitlines() or [""]:
        blocks.append({"type": "paragraph",
                       "content": [{"type": "text", "text": line or " "}]})
    return {"type": "doc", "version": 1, "content": blocks}


def create_issue(project_key: str, summary: str, description: str,
                 issue_type: str = "Task", assignee: str | None = None,
                 config: tuple[str, str, str] | None = None) -> dict:
    fields = {"project": {"key": project_key}, "summary": summary[:255],
              "issuetype": {"name": issue_type},
              "description": adf_paragraphs(description)}
    if assignee:
        fields["assignee"] = {"accountId": assignee}
    return request("POST", "/issue", {"fields": fields}, config=config)


def update_issue(issue_key: str, fields: dict,
                 config: tuple[str, str, str] | None = None) -> dict:
    return request("PUT", f"/issue/{issue_key}", {"fields": fields}, config=config)


def transition_issue(issue_key: str, to_status: str,
                     config: tuple[str, str, str] | None = None) -> dict:
    transitions = request("GET", f"/issue/{issue_key}/transitions",
                          config=config).get("transitions", [])
    match = next((t for t in transitions
                  if (t.get("to") or {}).get("name", "").lower() == to_status.lower()),
                 None)
    if match is None:
        raise JiraError(f"transition_unavailable: {to_status}")
    return request("POST", f"/issue/{issue_key}/transitions",
                   {"transition": {"id": match["id"]}}, config=config)


def get_issue(issue_key: str,
              config: tuple[str, str, str] | None = None) -> dict:
    return request("GET", f"/issue/{issue_key}?fields=status,assignee,summary",
                   config=config)

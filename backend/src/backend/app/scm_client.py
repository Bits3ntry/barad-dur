"""Code-host publishing: commit status + idempotent PR comment.

Credentials come from the organization's saved connection when one exists
(`app/integrations.py`); the `GITHUB_*` / `GITLAB_*` environment variables remain
as a fallback for deployments configured the old way. Nothing is posted unless a
token is present — callers must treat "not configured" as an explicit 503, never
as success.

Providers: GitHub, GitLab and Gitea. Only statuses and PR comments are ever
written; this module never pushes, edits a file or deletes anything.
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request

COMMENT_MARKER = "<!-- barad-dur:security-review -->"


class ScmError(RuntimeError):
    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


def provider_for(remote_url: str) -> str:
    """Decide the SCM provider from the remote host; never guess silently."""
    value = (remote_url or "").lower()
    if "gitlab" in value:
        return "gitlab"
    if "gitea" in value:
        return "gitea"
    if "github" in value:
        return "github"
    raise ScmError(f"scm_provider_unknown: {remote_url}")


def _tokens(provider: str, creds: dict | None) -> tuple[str, str]:
    """(token, base_url) for this call: saved connection first, env second."""
    if creds and creds.get("token"):
        return creds["token"], (creds.get("base_url") or "").rstrip("/")
    if provider == "gitlab":
        return (os.environ.get("GITLAB_TOKEN") or "",
                (os.environ.get("GITLAB_API_URL") or "").rstrip("/"))
    if provider == "gitea":
        return os.environ.get("GITEA_TOKEN") or "", \
            (os.environ.get("GITEA_URL") or "").rstrip("/")
    return (os.environ.get("GITHUB_TOKEN") or "",
            (os.environ.get("GITHUB_API_URL") or "").rstrip("/"))


def configured(provider: str = "github", creds: dict | None = None) -> bool:
    token, _base = _tokens(provider, creds)
    return bool(token)


def _github_api(creds: dict | None) -> str:
    _token, base = _tokens("github", creds)
    return (base or "https://api.github.com").rstrip("/")


def _call(url: str, method: str, headers: dict, payload: dict | None,
          prefix: str, timeout: float = 10.0):
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    for key, value in headers.items():
        request.add_header(key, value)
    request.add_header("User-Agent", "barad-dur")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode() or "{}"
            return json.loads(body)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode()[:300]
        raise ScmError(f"{prefix}_http_{exc.code}: {detail}", exc.code) from exc
    except urllib.error.URLError as exc:
        raise ScmError(f"{prefix}_unreachable: {exc.reason}") from exc


# ── GitHub ──────────────────────────────────────────────────────────────────

def _request(method: str, path: str, payload: dict | None = None,
             timeout: float = 10.0, creds: dict | None = None):
    token, _base = _tokens("github", creds)
    if not token:
        raise ScmError("scm_not_configured", 503)
    return _call(f"{_github_api(creds)}{path}", method,
                 {"Accept": "application/vnd.github+json",
                  "Authorization": f"token {token}"},
                 payload, "github", timeout)


def repo_slug(remote_url: str) -> str:
    """Extract owner/repo from an https or ssh remote URL."""
    value = (remote_url or "").strip().rstrip("/")
    if value.endswith(".git"):
        value = value[:-4]
    if "://" in value:
        tail = value.split("://", 1)[1]
        parts = tail.split("/", 1)
        if len(parts) != 2:
            raise ScmError("remote_url_not_parseable")
        return parts[1]
    if value.startswith("git@"):
        _host, _, path = value.partition(":")
        if not path:
            raise ScmError("remote_url_not_parseable")
        return path
    raise ScmError("remote_url_not_parseable")


def raw_file(remote_url: str, ref: str, path: str,
             creds: dict | None = None, timeout: float = 10.0) -> str | None:
    """One file, as the repository has it at `ref`.

    The console shows the code a scanner flagged; without this it can only show
    the snippet the SARIF happened to carry. Public repositories need no token,
    private ones use the saved connection. Returns None when the host says no —
    a missing file is a fact the caller has to display, not an exception to leak.
    """
    import urllib.error
    import urllib.parse
    import urllib.request

    provider = provider_for(remote_url)
    slug = repo_slug(remote_url)
    if not slug:
        return None
    quoted_path = urllib.parse.quote(path.lstrip("/"), safe="/")
    token, base = _tokens(provider, creds)
    host = urllib.parse.urlparse(remote_url).netloc
    scheme = urllib.parse.urlparse(remote_url).scheme or "https"
    headers = {"User-Agent": "barad-dur-console"}
    if provider == "gitlab":
        url = (f"{(base or f'{scheme}://{host}')}/api/v4/projects/"
               f"{urllib.parse.quote(slug, safe='')}/repository/files/"
               f"{urllib.parse.quote(path.lstrip('/'), safe='')}/raw?ref={ref}")
        if token:
            headers["PRIVATE-TOKEN"] = token
    elif provider == "github" and not base:
        url = f"https://api.github.com/repos/{slug}/contents/{quoted_path}?ref={ref}"
        headers["Accept"] = "application/vnd.github.raw"
        if token:
            headers["Authorization"] = f"token {token}"
    else:
        # Gitea and GitHub Enterprise share the shape: /api/v1/repos/<slug>/raw
        url = f"{(base or f'{scheme}://{host}')}/api/v1/repos/{slug}/raw/{quoted_path}?ref={ref}"
        if token:
            headers["Authorization"] = f"token {token}"
    try:
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(4 * 1024 * 1024)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ValueError):
        return None
    try:
        return body.decode("utf-8", errors="replace")
    except Exception:
        return None


def post_commit_status(slug: str, sha: str, state: str, description: str,
                       context: str = "barad-dur/security",
                       target_url: str | None = None, creds: dict | None = None):
    payload = {"state": state, "description": description[:140],
               "context": context}
    if target_url:
        payload["target_url"] = target_url
    return _request("POST", f"/repos/{slug}/statuses/{sha}", payload, creds=creds)


def upsert_pr_comment(slug: str, number: int, body: str,
                      creds: dict | None = None) -> dict:
    """One comment per PR: update ours in place instead of spamming."""
    existing = _request("GET", f"/repos/{slug}/issues/{number}/comments?per_page=100",
                        creds=creds)
    for comment in existing if isinstance(existing, list) else []:
        if COMMENT_MARKER in (comment.get("body") or ""):
            return _request("PATCH", f"/repos/{slug}/issues/comments/{comment['id']}",
                            {"body": body}, creds=creds)
    return _request("POST", f"/repos/{slug}/issues/{number}/comments",
                    {"body": body}, creds=creds)


def create_check_run(slug: str, sha: str, conclusion: str, title: str,
                     summary: str, annotations: list[dict] | None = None,
                     creds: dict | None = None):
    """Publish a GitHub check run with per-finding annotations (max 50)."""
    annotation_payload = []
    for item in (annotations or [])[:50]:
        annotation_payload.append({
            "path": item["path"],
            "start_line": max(1, int(item.get("line") or 1)),
            "end_line": max(1, int(item.get("line") or 1)),
            "annotation_level": item.get("level", "warning"),
            "message": (item.get("message") or "")[:900],
            "title": (item.get("title") or "")[:200],
        })
    payload = {
        "name": "barad-dûr / security",
        "head_sha": sha,
        "status": "completed",
        "conclusion": conclusion,
        "output": {"title": title[:200], "summary": summary[:65000],
                   "annotations": annotation_payload},
    }
    return _request("POST", f"/repos/{slug}/check-runs", payload, creds=creds)


def annotation_level(severity: str | None) -> str:
    return {"CRITICAL": "failure", "HIGH": "failure",
            "MEDIUM": "warning", "LOW": "notice"}.get((severity or "").upper(),
                                                       "warning")


# ── GitLab ──────────────────────────────────────────────────────────────────

def _gitlab_api(creds: dict | None) -> str:
    _token, base = _tokens("gitlab", creds)
    if base and base.endswith("/api/v4"):
        return base
    return (base or "https://gitlab.com") + "/api/v4"


def _gitlab_request(method: str, path: str, payload: dict | None = None,
                    timeout: float = 10.0, creds: dict | None = None):
    token, _base = _tokens("gitlab", creds)
    if not token:
        raise ScmError("scm_not_configured", 503)
    return _call(f"{_gitlab_api(creds)}{path}", method,
                 {"Accept": "application/json", "PRIVATE-TOKEN": token},
                 payload, "gitlab", timeout)


def _project_path(slug: str) -> str:
    return urllib.parse.quote(slug, safe="")


def post_gitlab_commit_status(slug: str, sha: str, state: str,
                              description: str, context: str = "barad-dur/security",
                              target_url: str | None = None,
                              creds: dict | None = None):
    payload = {"state": state, "name": context, "description": description[:140]}
    if target_url:
        payload["target_url"] = target_url
    return _gitlab_request("POST", f"/projects/{_project_path(slug)}/statuses/{sha}",
                           payload, creds=creds)


def upsert_gitlab_mr_note(slug: str, number: int, body: str,
                          creds: dict | None = None) -> dict:
    """One note per MR: update ours instead of posting duplicates."""
    project = _project_path(slug)
    existing = _gitlab_request(
        "GET", f"/projects/{project}/merge_requests/{number}/notes?per_page=100",
        creds=creds)
    for note in existing if isinstance(existing, list) else []:
        if COMMENT_MARKER in (note.get("body") or ""):
            return _gitlab_request(
                "PUT", f"/projects/{project}/merge_requests/{number}/notes/{note['id']}",
                {"body": body}, creds=creds)
    return _gitlab_request("POST", f"/projects/{project}/merge_requests/{number}/notes",
                           {"body": body}, creds=creds)


def gitlab_mr_versions(slug: str, number: int, creds: dict | None = None) -> dict:
    """Diff refs needed for an inline discussion; empty dict when unavailable."""
    payload = _gitlab_request(
        "GET", f"/projects/{_project_path(slug)}/merge_requests/{number}/versions",
        creds=creds)
    if isinstance(payload, list) and payload:
        return payload[0] or {}
    return payload if isinstance(payload, dict) else {}


def post_gitlab_mr_discussion(slug: str, number: int, body: str,
                              path: str, line: int, versions: dict,
                              creds: dict | None = None) -> dict:
    """One inline discussion anchored to a new line of the merge request diff."""
    position = {
        "position_type": "text",
        "base_sha": versions.get("base_sha"),
        "start_sha": versions.get("start_sha"),
        "head_sha": versions.get("head_sha"),
        "new_path": path,
        "new_line": max(1, int(line or 1)),
    }
    if not all(position.get(key) for key in ("base_sha", "start_sha", "head_sha")):
        raise ScmError("gitlab_mr_versions_incomplete")
    return _gitlab_request(
        "POST", f"/projects/{_project_path(slug)}/merge_requests/{number}/discussions",
        {"body": body, "position": position}, creds=creds)


# ── Gitea ───────────────────────────────────────────────────────────────────

def _gitea_api(creds: dict | None) -> str:
    _token, base = _tokens("gitea", creds)
    if not base:
        raise ScmError("gitea_base_url_missing")
    return base if base.endswith("/api/v1") else f"{base}/api/v1"


def _gitea_request(method: str, path: str, payload: dict | None = None,
                   timeout: float = 10.0, creds: dict | None = None):
    token, _base = _tokens("gitea", creds)
    if not token:
        raise ScmError("scm_not_configured", 503)
    return _call(f"{_gitea_api(creds)}{path}", method,
                 {"Accept": "application/json",
                  "Authorization": f"token {token}"},
                 payload, "gitea", timeout)


def post_gitea_commit_status(slug: str, sha: str, state: str, description: str,
                             context: str = "barad-dur/security",
                             target_url: str | None = None,
                             creds: dict | None = None):
    """Gitea commit statuses: success | failure | pending | error."""
    payload = {"state": state, "description": description[:140], "context": context}
    if target_url:
        payload["target_url"] = target_url
    return _gitea_request("POST", f"/repos/{slug}/statuses/{sha}", payload,
                          creds=creds)


def upsert_gitea_issue_comment(slug: str, number: int, body: str,
                               creds: dict | None = None) -> dict:
    existing = _gitea_request("GET", f"/repos/{slug}/issues/{number}/comments",
                              creds=creds)
    for comment in existing if isinstance(existing, list) else []:
        if COMMENT_MARKER in (comment.get("body") or ""):
            return _gitea_request("PATCH", f"/repos/{slug}/issues/comments/{comment['id']}",
                                  {"body": body}, creds=creds)
    return _gitea_request("POST", f"/repos/{slug}/issues/{number}/comments",
                          {"body": body}, creds=creds)


# ── Discovery (read-only) ───────────────────────────────────────────────────

def list_repositories(provider: str, creds: dict, limit: int = 100) -> list[dict]:
    """Repositories the token can read. Never creates or changes anything."""
    if provider == "github":
        rows = _request("GET", f"/user/repos?per_page={min(limit, 100)}&sort=updated",
                        creds=creds)
        return [{"name": row.get("full_name") or row.get("name"),
                 "url": row.get("clone_url") or row.get("html_url"),
                 "private": bool(row.get("private")),
                 "default_branch": row.get("default_branch")}
                for row in rows if isinstance(row, dict)]
    if provider == "gitlab":
        rows = _gitlab_request(
            "GET", f"/projects?membership=true&per_page={min(limit, 100)}&order_by=last_activity_at",
            creds=creds)
        return [{"name": row.get("path_with_namespace"),
                 "url": row.get("http_url_to_repo") or row.get("web_url"),
                 "private": row.get("visibility") != "public",
                 "default_branch": row.get("default_branch")}
                for row in rows if isinstance(row, dict)]
    if provider == "gitea":
        rows = _gitea_request("GET", f"/user/repos?limit={min(limit, 50)}", creds=creds)
        return [{"name": row.get("full_name"),
                 "url": row.get("clone_url") or row.get("html_url"),
                 "private": bool(row.get("private")),
                 "default_branch": row.get("default_branch")}
                for row in rows if isinstance(row, dict)]
    raise ScmError(f"scm_provider_unsupported: {provider}")

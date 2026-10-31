"""GitHub publishing: commit status + idempotent PR comment.

Configuration (deployment-owned, never logged):
  GITHUB_API_URL  default https://api.github.com
  GITHUB_TOKEN    token with repo:status and pull_requests:write

Nothing is posted unless the token is present; callers must treat "not
configured" as an explicit 503, not as success.
"""
import json
import os
import urllib.error
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
    if "github" in value:
        return "github"
    raise ScmError(f"scm_provider_unknown: {remote_url}")


def configured(provider: str = "github") -> bool:
    if provider == "gitlab":
        return bool(os.environ.get("GITLAB_TOKEN"))
    return bool(os.environ.get("GITHUB_TOKEN"))


def _api() -> str:
    return (os.environ.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/")


def _request(method: str, path: str, payload: dict | None = None,
             timeout: float = 10.0) -> dict:
    token = os.environ.get("GITHUB_TOKEN") or ""
    if not token:
        raise ScmError("scm_not_configured", 503)
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(f"{_api()}{path}", data=data, method=method)
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("Authorization", f"token {token}")
    request.add_header("User-Agent", "barad-dur")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode() or "{}"
            return json.loads(body)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode()[:300]
        raise ScmError(f"github_http_{exc.code}: {detail}", exc.code) from exc
    except urllib.error.URLError as exc:
        raise ScmError(f"github_unreachable: {exc.reason}") from exc


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
        host, _, path = value.partition(":")
        if not path:
            raise ScmError("remote_url_not_parseable")
        return path
    raise ScmError("remote_url_not_parseable")


def post_commit_status(slug: str, sha: str, state: str, description: str,
                       context: str = "barad-dur/security", target_url: str | None = None):
    payload = {"state": state, "description": description[:140],
               "context": context}
    if target_url:
        payload["target_url"] = target_url
    return _request("POST", f"/repos/{slug}/statuses/{sha}", payload)


def upsert_pr_comment(slug: str, number: int, body: str) -> dict:
    """One comment per PR: update ours in place instead of spamming."""
    existing = _request("GET", f"/repos/{slug}/issues/{number}/comments?per_page=100")
    for comment in existing if isinstance(existing, list) else []:
        if COMMENT_MARKER in (comment.get("body") or ""):
            return _request("PATCH", f"/repos/{slug}/issues/comments/{comment['id']}",
                            {"body": body})
    return _request("POST", f"/repos/{slug}/issues/{number}/comments", {"body": body})


# ── GitLab ──────────────────────────────────────────────────────────────────

def _gitlab_api() -> str:
    return (os.environ.get("GITLAB_API_URL")
            or "https://gitlab.com/api/v4").rstrip("/")


def _gitlab_request(method: str, path: str, payload: dict | None = None,
                    timeout: float = 10.0):
    import urllib.parse

    token = os.environ.get("GITLAB_TOKEN") or ""
    if not token:
        raise ScmError("scm_not_configured", 503)
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(f"{_gitlab_api()}{path}", data=data,
                                     method=method)
    request.add_header("Accept", "application/json")
    request.add_header("PRIVATE-TOKEN", token)
    request.add_header("User-Agent", "barad-dur")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode() or "{}"
            return json.loads(body)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode()[:300]
        raise ScmError(f"gitlab_http_{exc.code}: {detail}", exc.code) from exc
    except urllib.error.URLError as exc:
        raise ScmError(f"gitlab_unreachable: {exc.reason}") from exc


def _project_path(slug: str) -> str:
    import urllib.parse

    return urllib.parse.quote(slug, safe="")


def post_gitlab_commit_status(slug: str, sha: str, state: str,
                              description: str, context: str = "barad-dur/security",
                              target_url: str | None = None):
    payload = {"state": state, "name": context, "description": description[:140]}
    if target_url:
        payload["target_url"] = target_url
    return _gitlab_request("POST", f"/projects/{_project_path(slug)}/statuses/{sha}",
                           payload)


def upsert_gitlab_mr_note(slug: str, number: int, body: str) -> dict:
    """One note per MR: update ours instead of posting duplicates."""
    project = _project_path(slug)
    existing = _gitlab_request(
        "GET", f"/projects/{project}/merge_requests/{number}/notes?per_page=100")
    for note in existing if isinstance(existing, list) else []:
        if COMMENT_MARKER in (note.get("body") or ""):
            return _gitlab_request(
                "PUT", f"/projects/{project}/merge_requests/{number}/notes/{note['id']}",
                {"body": body})
    return _gitlab_request("POST", f"/projects/{project}/merge_requests/{number}/notes",
                           {"body": body})

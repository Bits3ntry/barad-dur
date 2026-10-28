"""Git context detection: branch, SHAs, base reference and event normalisation.

One implementation for the local CLI, a Git hook, `act` and GitHub Actions. The
GitHub environment is read from the standard `GITHUB_*` variables and, when
present, from the event payload file, so nothing about CI needs its own code
path.

When a trustworthy base SHA does not exist the context records that fact instead
of guessing: the decision engine then asks for a conservative SBOM and stores the
reason `base_reference_unavailable`.
"""
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .errors import GitError

EVENTS = ("local", "push", "pr", "release", "dispatch")

GITHUB_EVENT_MAP = {
    "pull_request": "pr",
    "pull_request_target": "pr",
    "push": "push",
    "release": "release",
    "workflow_dispatch": "dispatch",
    "schedule": "dispatch",
}

_ZERO_SHA = re.compile(r"^0+$")
_SHA = re.compile(r"^[0-9a-f]{7,64}$")
# A ref reaching `git` as one argv element still must not look like an option.
_REF_FORBIDDEN = re.compile(r"^\-|[\s\x00-\x1f]")


def validate_ref(ref):
    """Return a safe revision string, or None when it must not reach git."""
    if not isinstance(ref, str):
        return None
    candidate = ref.strip()
    if not candidate or len(candidate) > 200:
        return None
    if _REF_FORBIDDEN.search(candidate):
        return None
    return candidate


@dataclass
class GitContext:
    repository_root: Path
    available: bool = False
    event: str = "local"
    event_source: str = "cli"
    branch: str = None
    commit_sha: str = None
    head_sha: str = None
    base_sha: str = None
    base_ref: str = None
    base_resolution: str = "unavailable"
    base_problem: str = None
    pull_request: str = None
    tag: str = None
    is_merge: bool = False
    root_commit: bool = False
    # Relative path from the Git top level to the configured repository root
    # ("" when they are the same directory). Diff paths are Git-root relative.
    repository_offset: str = ""
    problems: list = field(default_factory=list)

    def public(self):
        return {
            "event": self.event,
            "event_source": self.event_source,
            "branch": self.branch,
            "commit_sha": self.commit_sha,
            "base_sha": self.base_sha,
            "head_sha": self.head_sha,
            "base_ref": self.base_ref,
            "base_resolution": self.base_resolution,
            "repository_offset": self.repository_offset,
            "pull_request": self.pull_request,
            "tag": self.tag,
        }


def _run_git(repo, args, check=False):
    env = dict(os.environ)
    env.update({"GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C", "GIT_PAGER": "cat"})
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as error:
        if check:
            raise GitError(f"git {' '.join(args)} failed: {error}") from None
        return 1, "", str(error)
    if check and result.returncode != 0:
        raise GitError(f"git {' '.join(args)} failed: {result.stderr.strip() or result.returncode}")
    return result.returncode, result.stdout, result.stderr


def normalize_event(value):
    if value is None:
        return "local"
    candidate = str(value).strip().lower()
    if candidate in EVENTS:
        return candidate
    if candidate in GITHUB_EVENT_MAP:
        return GITHUB_EVENT_MAP[candidate]
    raise GitError(f"unsupported event {value!r}; expected one of: {', '.join(EVENTS)}")


def event_from_environment(environ=None):
    env = environ or os.environ
    raw = env.get("GITHUB_EVENT_NAME")
    if not raw:
        return "local", "default"
    return normalize_event(raw), "github_env"


def _load_event_payload(environ):
    path = environ.get("GITHUB_EVENT_PATH")
    if not path:
        return {}, "github_env"
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError):
        return {}, "github_env_unreadable"
    return (payload if isinstance(payload, dict) else {}), "github_payload"


def _resolve_commit(repo, ref):
    ref = validate_ref(ref)
    if not ref:
        return None
    status, out, _ = _run_git(repo, ["rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"])
    if status != 0:
        return None
    return out.strip() or None


def _merge_base(repo, left, right):
    status, out, _ = _run_git(repo, ["merge-base", left, right])
    if status != 0:
        return None
    return out.strip() or None


def _previous_tag(repo, head):
    status, out, _ = _run_git(repo, ["describe", "--tags", "--abbrev=0", f"{head}^"])
    if status != 0:
        return None
    return out.strip() or None


def _parent_count(repo, head):
    status, out, _ = _run_git(repo, ["rev-list", "--parents", "-n", "1", head])
    if status != 0 or not out.strip():
        return 0
    return max(len(out.split()) - 1, 0)


def detect_git_context(repo_root, *, event=None, base_ref=None, environ=None):
    """Collect everything the change detector needs, without mutating the repo."""
    env = environ or os.environ
    repo = Path(repo_root).resolve()
    context = GitContext(repository_root=repo)

    status, out, err = _run_git(repo, ["rev-parse", "--show-toplevel"])
    if status != 0:
        context.available = False
        context.problems.append({"code": "not_a_git_repository", "detail": err.strip() or "git rev-parse failed"})
        inferred_event, source = event_from_environment(env)
        context.event = normalize_event(event) if event else inferred_event
        context.event_source = "cli" if event else source
        return context

    context.available = True
    context.repository_root = Path(out.strip())
    try:
        offset = Path(repo).resolve().relative_to(context.repository_root.resolve())
        context.repository_offset = "" if str(offset) == "." else offset.as_posix()
    except ValueError:  # the Git top level is not an ancestor; keep Git-root scoping
        context.repository_offset = ""

    payload, payload_source = _load_event_payload(env)
    inferred_event, env_source = event_from_environment(env)
    context.event = normalize_event(event) if event else inferred_event
    context.event_source = "cli" if event else (payload_source if payload else env_source)

    head = _resolve_commit(repo, "HEAD")
    context.head_sha = head
    context.commit_sha = head
    if head is None:
        context.problems.append({"code": "head_unresolvable", "detail": "HEAD is not a commit"})

    status, out, _ = _run_git(repo, ["rev-parse", "--abbrev-ref", "HEAD"])
    branch = out.strip() if status == 0 else None
    if branch == "HEAD":
        tag_status, tag_out, _ = _run_git(repo, ["describe", "--tags", "--exact-match", "HEAD"])
        branch = None
        if tag_status == 0:
            context.tag = tag_out.strip()
    context.branch = env.get("GITHUB_HEAD_REF") or env.get("GITHUB_REF_NAME") or branch

    pull_request = payload.get("pull_request") if isinstance(payload.get("pull_request"), dict) else {}
    number = payload.get("number") or pull_request.get("number")
    if number:
        context.pull_request = str(number)
    else:
        match = re.match(r"^refs/pull/(\d+)/", env.get("GITHUB_REF", ""))
        if match:
            context.pull_request = match.group(1)

    release = payload.get("release") if isinstance(payload.get("release"), dict) else {}
    context.tag = context.tag or release.get("tag_name") or (env.get("GITHUB_REF_NAME") if str(env.get("GITHUB_REF", "")).startswith("refs/tags/") else None)

    if head:
        parents = _parent_count(repo, head)
        context.is_merge = parents > 1
        status, out, _ = _run_git(repo, ["rev-list", "--max-parents=0", "HEAD"])
        context.root_commit = len((out or "").split()) == 1 and parents == 0

    if base_ref and validate_ref(base_ref) is None:
        context.problems.append({
            "code": "base_ref_rejected",
            "detail": f"refusing an unsafe base reference: {str(base_ref)[:80]!r}",
        })
    base_candidates = _base_candidates(context, base_ref, payload, env)
    context.base_ref = base_candidates[0][0] if base_candidates else None
    resolved_from = None
    for ref, resolution in base_candidates:
        commit = _resolve_commit(repo, ref)
        if commit is None:
            continue
        if context.event == "pr" and head:
            # A pull request is the whole branch, never just its last commit.
            merged = _merge_base(repo, commit, head)
            if merged:
                commit = merged
                resolution = f"merge_base_of_{resolution}"
        context.base_sha = commit
        context.base_resolution = resolution
        resolved_from = ref
        break

    if context.base_sha is None:
        context.base_resolution = "unavailable"
        context.base_problem = "base_reference_unavailable"
        context.problems.append({
            "code": "base_reference_unavailable",
            "detail": "no trustworthy base commit; the SBOM is generated conservatively",
        })
    elif resolved_from:
        context.base_ref = resolved_from
    return context


def _base_candidates(context, base_ref, payload, env):
    """Ordered (ref, resolution) pairs; the first resolvable one wins."""
    candidates = []
    if validate_ref(base_ref):
        candidates.append((validate_ref(base_ref), "explicit_base_ref"))
    if env.get("GITHUB_BASE_SHA") and not _ZERO_SHA.match(env["GITHUB_BASE_SHA"]):
        candidates.append((env["GITHUB_BASE_SHA"], "github_base_sha"))
    before = payload.get("before") or env.get("GITHUB_EVENT_BEFORE") or env.get("GITHUB_BEFORE")
    if before and not _ZERO_SHA.match(str(before)):
        candidates.append((str(before), "github_before"))

    if context.event == "release":
        tag = context.tag
        if tag:
            status, out, _ = _run_git(context.repository_root, ["describe", "--tags", "--abbrev=0", f"{tag}^"])
            if status == 0 and out.strip():
                candidates.append((out.strip(), "previous_tag"))
        if context.head_sha:
            previous = _previous_tag(context.repository_root, context.head_sha)
            if previous:
                candidates.append((previous, "previous_tag"))
    if env.get("GITHUB_BASE_REF"):
        candidates.append((f"refs/remotes/origin/{env['GITHUB_BASE_REF']}", "github_base_ref"))
        candidates.append((env["GITHUB_BASE_REF"], "github_base_ref"))

    if context.event in ("local", "push", "dispatch") and context.head_sha:
        # HEAD is the working-tree baseline: uncommitted edits are compared to it.
        candidates.append((context.head_sha, "head_working_tree"))
    if context.event in ("local", "push") and context.head_sha:
        candidates.append((f"{context.head_sha}^", "previous_commit"))
    return candidates

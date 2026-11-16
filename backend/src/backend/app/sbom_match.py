"""Which project and component does a hand-delivered SBOM belong to?

Trivy writes the *scanned path* as the root component (`.` when the target is the
repository), so a real artifact frequently does not name its application at all.
Detection is therefore a ranked guess over four independent signals — the root
name, the file name, the repositories registered against a component, and the
component names themselves — and it always returns the reason it chose, because
the operator corrects the guess on screen and has to know why it was made.

Nothing here writes: `detect()` answers, the upload endpoint decides.
"""
from __future__ import annotations

import re

from backend.app import models

# Tokens that appear in every scanner artifact and in half the paths on a
# developer machine. Matching on one of these picks a project by accident, which
# is worse than answering "the document does not say". Deliberately absent:
# `backend`, `frontend`, `web`, `api`, `service` — those are the component names
# this estate actually uses, and dropping them hid the one signal a Trivy file
# name can carry (`aurea-frontend.cdx.json`).
NOISE = frozenset({
    "json", "cdx", "cyclonedx", "spdx", "bom", "sbom", "lock", "lockfile",
    "requirements", "package", "poetry", "pipfile", "gemfile", "pom", "gradle",
    "sum", "tmp", "temp", "home", "users", "workspace", "workspaces", "desktop",
    "documents", "downloads", "github", "gitlab", "gitea", "bitbucket", "com",
    "org", "net", "io", "git", "repo", "node_modules",
})

VERSION_RE = re.compile(r"(?<![\w.])v?(\d+\.\d+(?:\.\d+)?)(?![\w.])")


def tokens(value: str | None) -> list[str]:
    return [part for part in re.split(r"[^a-z0-9]+", str(value or "").lower())
            if part]


def meaningful(value: str | None) -> set[str]:
    """Tokens that can identify something, noise removed."""
    return {part for part in tokens(value) if part not in NOISE and len(part) > 1}


def normalize_root(value: str | None) -> str:
    """The last path segment of a root name, lowercased.

    `./backend/`, `git@github.com:aurea/backend.git` and `/home/dev/aurea/backend`
    all name `backend`. A bare `.` (Trivy scanning the repository root) names
    nothing, which is the honest answer and not an empty string to paper over.
    """
    text = str(value or "").strip().replace("\\", "/").rstrip("/")
    if not text:
        return ""
    text = re.sub(r"\.git$", "", text, flags=re.IGNORECASE)
    if ":" in text:
        text = text.rsplit(":", 1)[-1]
    if "/" in text:
        text = text.rsplit("/", 1)[-1]
    text = text.strip().strip(".").lower()
    return "" if text in ("", ".") else text


def filename_stem(filename: str | None) -> str:
    """`aurea-frontend.cdx.json` → `aurea-frontend`."""
    text = str(filename or "").strip()
    for suffix in (".json", ".cdx", ".cyclonedx", ".bom"):
        if text.lower().endswith(suffix):
            text = text[: -len(suffix)]
    return text


def _repo_keys(repositories: list[models.Repository]) -> set[str]:
    keys: set[str] = set()
    for repository in repositories:
        for value in (repository.name, repository.remote_url):
            key = normalize_root(value)
            if key:
                keys.add(key)
    return keys


def _project_row(project: models.Project, reason: str) -> dict:
    return {"id": project.id, "slug": project.slug, "name": project.name,
            "reason": reason}


def _component_row(component: models.ApplicationComponent, reason: str) -> dict:
    return {"id": component.id, "slug": component.slug, "name": component.name,
            "kind": component.kind, "reason": reason}


def _project_score(project: models.Project, root_key: str, root_tokens: set[str],
                   file_tokens: set[str], project_repo_keys: set[str],
                   components: list[models.ApplicationComponent],
                   component_repo_keys: dict[str, set[str]]) -> tuple[int, str | None]:
    """How strongly this project owns the document, best reason first.

    Ordered, not weighted: the first rule that fires is the answer, and the score
    exists only to rank candidates against each other.
    """
    slug = (project.slug or "").lower()
    name_key = normalize_root(project.name)
    if root_key:
        if root_key == slug:
            return 100, "project-slug"
        if root_key == name_key:
            return 95, "project-name"
        if root_key in project_repo_keys:
            return 90, "repository"
        for component in components:
            if root_key in {component.slug.lower(), (component.name or "").lower()}:
                return 85, "component-name"
            if root_key in component_repo_keys.get(component.id, set()):
                return 80, "repository"
    project_tokens = {slug} | meaningful(project.name)
    if root_tokens & project_tokens:
        return 70, "root-contains-project"
    if file_tokens & project_tokens:
        return 60, "filename"
    for component in components:
        component_tokens = meaningful(component.name) | {component.slug.lower()}
        if root_tokens & component_tokens or file_tokens & component_tokens:
            return 50, "component-name"
    return 0, None


def _component_score(component: models.ApplicationComponent, root_key: str,
                     root_tokens: set[str], file_tokens: set[str],
                     repo_keys: set[str]) -> tuple[int, str | None]:
    slug = (component.slug or "").lower()
    name_key = (component.name or "").lower()
    if root_key:
        if root_key == slug:
            return 100, "component-slug"
        if root_key == name_key:
            return 95, "component-name"
        if root_key in repo_keys:
            return 90, "repository"
        if slug and (root_key.endswith(f"-{slug}") or root_key.startswith(f"{slug}-")):
            return 80, "component-name"
    component_tokens = meaningful(component.name) | {slug}
    if root_tokens & component_tokens:
        return 70, "component-name"
    if file_tokens & component_tokens:
        return 55, "filename"
    return 0, None


def detect(session, org_id: str, parsed: dict,
           filename: str | None = None) -> dict:
    """Rank the projects that could own this document, and the component inside.

    Returns `detected` (what the screen pre-selects) plus `candidates` (what the
    operator picks from when the guess is wrong). A `None` detected project is a
    fact — the document does not name its application — never a default.
    """
    root = str(parsed.get("project_name") or "")
    root_key = normalize_root(root)
    stem = filename_stem(filename)
    root_tokens = meaningful(root_key)
    file_tokens = meaningful(stem) | meaningful(filename)

    projects = (session.query(models.Project).filter_by(org_id=org_id)
                .order_by(models.Project.name).all())
    components = (session.query(models.ApplicationComponent)
                  .filter_by(org_id=org_id).all())
    components_by_project: dict[str, list[models.ApplicationComponent]] = {}
    for component in components:
        components_by_project.setdefault(component.project_id, []).append(component)

    repositories = {row.id: row
                    for row in session.query(models.Repository).filter_by(org_id=org_id).all()}
    component_repositories: dict[str, list[models.Repository]] = {}
    for link in (session.query(models.ComponentRepository).filter_by(org_id=org_id)
                 .filter(models.ComponentRepository.removed_at.is_(None)).all()):
        repository = repositories.get(link.repository_id)
        if repository is not None:
            component_repositories.setdefault(link.component_id, []).append(repository)
    project_repositories: dict[str, list[models.Repository]] = {}
    for link in (session.query(models.ProjectRepository).filter_by(org_id=org_id)
                 .filter(models.ProjectRepository.removed_at.is_(None)).all()):
        repository = repositories.get(link.repository_id)
        if repository is not None:
            project_repositories.setdefault(link.project_id, []).append(repository)

    component_repo_keys = {component_id: _repo_keys(rows)
                           for component_id, rows in component_repositories.items()}

    candidates = []
    for project in projects:
        score, reason = _project_score(
            project, root_key, root_tokens, file_tokens,
            _repo_keys(project_repositories.get(project.id, [])),
            components_by_project.get(project.id, []), component_repo_keys)
        if score:
            candidates.append((score, _project_row(project, reason or "none")))

    # A file name can also name the component of a project whose own name says
    # nothing (`aurea-frontend.cdx.json` → project `aurea`, component `frontend`).
    candidates.sort(key=lambda item: (-item[0], item[1]["name"].lower()))
    best = candidates[0][1] if candidates else None

    component = None
    detected_components = []
    if best is not None:
        for row in components_by_project.get(best["id"], []):
            score, reason = _component_score(
                row, root_key, root_tokens, file_tokens,
                component_repo_keys.get(row.id, set()))
            if score:
                detected_components.append((score, _component_row(row, reason or "none")))
        detected_components.sort(key=lambda item: (-item[0], item[1]["name"].lower()))
        component = detected_components[0][1] if detected_components else None

    version = parsed.get("project_version") or None
    version_from = "document" if version else None
    if not version:
        found = VERSION_RE.search(stem)
        if found:
            version, version_from = found.group(1), "filename"

    return {
        "document": {
            "root_name": root or None,
            "root_names_nothing": root_key == "",
            "root_version": parsed.get("project_version") or None,
            "spec_version": parsed.get("spec_version"),
            "filename": filename,
        },
        "detected": {
            "project": best,
            "component": component,
            "version": version,
            "version_from": version_from,
        },
        "candidates": {
            "projects": [row for _score, row in candidates[:5]],
            "components": [row for _score, row in detected_components[:8]],
        },
    }

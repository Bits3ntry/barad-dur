"""Pipeline reads: the Action runs, one row per workflow execution.

Read-only by design. An Action is announced and executed through the scan flow
(`POST /scans` with `origin=ci`); this router only answers "what did the pipeline
do", so the console never needs the `ci_runs` registry — which nothing writes in
this deployment — to show a run.

Two shapes of the same data:

- `/commits` is what the screen reads: runs folded into one row per commit,
  because a retried workflow leaves five rows on one sha and the operator is
  asking about the commit.
- `/actions` is the flat run list, unpaged by commit, for callers that want one
  row per execution.
"""
from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app import models, pipeline, pipeline_builder, projects as projects_ref, scan_actions
from backend.app.auth import require_org
from backend.app.db import get_session

router = APIRouter(prefix="/api/v1/pipeline", tags=["pipeline"])


def _ci_jobs(session: Session, org: models.Organization) -> list[models.ScanJob]:
    """Every pipeline run of the organization, newest first.

    Only `origin=ci`: a scan started from the CLI or the console is a scanner
    run, and those belong to orchestration where an operator can act on them.
    """
    return (session.query(models.ScanJob)
            .filter_by(org_id=org.id, origin="ci")
            .order_by(models.ScanJob.created_at.desc()).all())


def _rows(session: Session, jobs: list[models.ScanJob]) -> list[dict]:
    ids = [job.id for job in jobs]
    found = pipeline.summaries(session, ids)
    counted = pipeline.reported(session, ids)
    return [pipeline.row(job, found.get(job.id), counted.get(job.id)) for job in jobs]


def _counters(rows: list[dict]) -> dict:
    """Run-level totals over the whole organization.

    Counted over every run, never over the page: a toolbar that adds up only the
    rows it is showing tells the truth about the page and lies about the
    pipeline. `superseded` is not a pass — its findings belong to a newer run.
    """
    return {
        "running": sum(1 for item in rows if item["verdict"] == "running"),
        "pass": sum(1 for item in rows
                    if item["verdict"] == "pass" and not item["superseded"]),
        "fail": sum(1 for item in rows if item["verdict"] == "fail"),
        "superseded": sum(1 for item in rows if item["superseded"]),
    }


@router.get("/commits")
def commits(limit: int = Query(default=25, ge=1, le=200),
            offset: int = Query(default=0, ge=0),
            org: models.Organization = Depends(require_org),
            session: Session = Depends(get_session)) -> dict:
    """Action runs folded into one row per commit, newest commit first.

    The console pages COMMITS, not runs: a page carries every attempt on each of
    its commits, so a group is never cut in half between two pages.
    """
    rows = _rows(session, _ci_jobs(session, org))
    groups = pipeline.grouped(rows)
    return {
        "data": groups[offset:offset + limit],
        "total": len(groups),
        "limit": limit,
        "offset": offset,
        "counters": {"commits": len(groups), "runs": len(rows), **_counters(rows)},
    }


@router.get("/actions")
def actions(limit: int = Query(default=100, ge=1, le=500),
            offset: int = Query(default=0, ge=0),
            org: models.Organization = Depends(require_org),
            session: Session = Depends(get_session)) -> dict:
    """The latest CI Action runs, newest first, one row per execution."""
    rows = _rows(session, _ci_jobs(session, org))
    return {
        "data": rows[offset:offset + limit],
        "total": len(rows),
        "limit": limit,
        "offset": offset,
        "counters": _counters(rows),
    }


# ── the builder: what a pipeline may ask for, and the file that asks for it ───

TRIGGERS = [
    {"name": "push", "label": "on every push",
     "detail": "a merge lands and the default branch moves"},
    {"name": "pull_request", "label": "on every pull request",
     "detail": "the check that blocks a merge"},
    {"name": "manual", "label": "on demand",
     "detail": "a button, for a re-run after a fix"},
]


def _repository_row(row: models.Repository) -> dict:
    return {
        "id": row.id, "name": row.name, "provider": row.provider,
        "remote_url": row.remote_url,
        "last_commit_sha": row.last_commit_sha,
        # What the generated file will look like: a repository registered as
        # `git` still gets the portable script until its provider is known.
        "ci": pipeline_builder.provider_for(row.provider, row.remote_url),
        "ci_label": pipeline_builder.PROVIDERS[
            pipeline_builder.provider_for(row.provider, row.remote_url)]["label"],
    }


@router.get("/blueprint")
def blueprint(project: str = Query(...),
              org: models.Organization = Depends(require_org),
              session: Session = Depends(get_session)) -> dict:
    """Everything the builder needs for one project: components, their remotes,
    and the catalog with what CI may and may not ask for.

    `ci_allowed` is not a UI opinion: it is `push_allowed` evaluated on the same
    task set the platform would receive, so a disabled card and a refused ticket
    always agree.
    """
    project_row = projects_ref.by_ref(session, org.id, project)
    if project_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")

    components = (session.query(models.ApplicationComponent)
                  .filter_by(project_id=project_row.id)
                  .order_by(models.ApplicationComponent.name).all())
    links = (session.query(models.ComponentRepository)
             .filter_by(org_id=org.id)
             .filter(models.ComponentRepository.removed_at.is_(None)).all())
    repositories = {row.id: row for row in
                    (session.query(models.Repository).filter_by(org_id=org.id).all())}
    repos_by_component: dict[str, list[dict]] = {}
    for link in links:
        repo = repositories.get(link.repository_id)
        if repo is None:
            continue
        repos_by_component.setdefault(link.component_id, []).append(_repository_row(repo))

    actions = []
    for row in scan_actions.catalog():
        tasks = scan_actions.build_tasks(row["name"])
        allowed, reason = scan_actions.push_allowed(tasks, network=row["network"])
        actions.append({
            **row,
            "tasks_detail": tasks,
            "ci_allowed": allowed,
            # A blocked action is not hidden: it is the answer to "how far can a
            # pipeline go", and it names what would have to happen instead.
            "blocked_reason": None if allowed else reason,
        })

    return {
        "data": {
            "project": {"slug": project_row.slug, "name": project_row.name},
            "components": [{
                "id": row.id, "slug": row.slug, "name": row.name, "kind": row.kind,
                "repositories": repos_by_component.get(row.id, []),
            } for row in components],
            "actions": actions,
            "triggers": TRIGGERS,
            # The console cannot know how a runner reaches this API; this is the
            # operator's only chance to be told, so a configured value wins.
            "api_url": os.environ.get("PLATFORM_PUBLIC_URL", "").rstrip("/") or None,
        },
    }


@router.get("/snippet")
def snippet(project: str = Query(...),
            component: str | None = Query(default=None),
            actions: str = Query(default=""),
            provider: str | None = Query(default=None),
            triggers: str = Query(default="push,pull_request"),
            branch: str = Query(default="main"),
            api_url: str | None = Query(default=None),
            org: models.Organization = Depends(require_org),
            session: Session = Depends(get_session)) -> dict:
    """The workflow file for this selection, plus where it goes and what it needs."""
    project_row = projects_ref.by_ref(session, org.id, project)
    if project_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")

    wanted = [name.strip() for name in actions.split(",") if name.strip()]
    if not wanted:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "pick at least one action")
    unknown = [name for name in wanted if scan_actions.action(name) is None]
    if unknown:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"unknown action(s) {unknown}; known: {sorted(scan_actions.ACTIONS)}")
    for name in wanted:
        spec = scan_actions.action(name)
        allowed, reason = scan_actions.push_allowed(
            scan_actions.build_tasks(name), network=spec["network"])
        if not allowed:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"{name}: {reason}")

    repository = None
    component_ref = None
    if component:
        row = session.get(models.ApplicationComponent, component)
        if row is None or row.project_id != project_row.id:
            row = (session.query(models.ApplicationComponent)
                   .filter_by(project_id=project_row.id, slug=component).one_or_none())
        if row is None or row.project_id != project_row.id:
            row = (session.query(models.ApplicationComponent)
                   .filter_by(project_id=project_row.id, name=component).one_or_none())
        if row is not None:
            # The file must name the component the way a person reads it. The id
            # is the builder's handle; the slug is what the ticket carries and
            # what the Pipelines row will show.
            component_ref = row.slug or row.name
        link = (session.query(models.ComponentRepository)
                .filter_by(org_id=org.id, component_id=row.id if row else component)
                .filter(models.ComponentRepository.removed_at.is_(None)).first())
        if link is not None:
            repository = session.get(models.Repository, link.repository_id)

    chosen_provider = provider or pipeline_builder.provider_for(
        repository.provider if repository else None,
        repository.remote_url if repository else None)
    chosen_triggers = [name.strip() for name in triggers.split(",") if name.strip()]

    data = pipeline_builder.snippet(
        project=project_row.slug, component=component_ref, actions=wanted,
        provider=chosen_provider, triggers=chosen_triggers, branch=branch,
        api_url=(api_url or os.environ.get("PLATFORM_PUBLIC_URL") or None),
    )
    data["repository"] = _repository_row(repository) if repository else None
    return {"data": data}

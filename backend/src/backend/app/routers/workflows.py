"""Workflows: the catalog's profiles, plus the ones an organisation writes.

The list is two sources with one shape. `system` is `surface_catalog.json` — the
engine's own nine, read-only, cloneable. `mine` is `scan_workflows` — the same
document, validated by the engine's rules (`surface_workflow.normalize`), so a
custom workflow can be planned, launched and audited exactly like a catalog one.

Cloning is a copy, never a parent: the catalog moves when Shauron ships, and an
organisation that edited `recon.simple` did not ask to inherit the next release.
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from backend.app import auth, models, surface_plan, surface_workflow
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1/surface/workflows", tags=["surface"])


def _row_data(row: models.ScanWorkflow) -> dict:
    return {
        "id": row.id, "slug": row.slug, "origin": "org",
        "label": row.label, "question": row.question or "",
        "target_kind": row.target_kind, "level": row.level,
        "plane": json.loads(row.plane or "[]"),
        "stages": json.loads(row.stages or "[]"),
        "limits": json.loads(row.limits or "{}"),
        "cloned_from": row.cloned_from, "created_by": row.created_by,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "archived": row.archived,
    }


def _system_data(name: str, document: dict) -> dict:
    return {
        "id": name, "slug": name, "origin": "system", "label": document.get("label"),
        "question": document.get("question") or "", "target_kind": document.get("target_kind"),
        "level": document.get("level"), "plane": document.get("plane") or [],
        "stages": document.get("stages") or [], "limits": document.get("limits") or {},
        "cloned_from": None, "created_by": "shauron", "created_at": None, "archived": False,
    }


class StageIn(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(min_length=2, max_length=96)
    from_stage: str = Field(default="targets", alias="from")
    tools: list[str] = []


class WorkflowIn(BaseModel):
    label: str = Field(min_length=2, max_length=128)
    slug: str | None = Field(default=None, max_length=90)
    question: str = ""
    target_kind: str = "domain"
    level: str = "simple"
    plane: list[str] = ["cloud"]
    stages: list[StageIn] = []
    limits: dict = {}
    clone_from: str | None = None
    actor: str = Field(default="console", max_length=255)


class WorkflowPatch(BaseModel):
    label: str | None = None
    question: str | None = None
    level: str | None = None
    plane: list[str] | None = None
    stages: list[StageIn] | None = None
    limits: dict | None = None
    actor: str = Field(default="console", max_length=255)


def _slug_for(payload: WorkflowIn) -> str:
    short = (payload.slug or payload.label).strip().lower()
    short = "".join(character if character.isalnum() else "-" for character in short)
    short = "-".join(part for part in short.split("-") if part)
    if not short:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            {"code": "workflow.bad_slug", "at": payload.label})
    return surface_workflow.PREFIX + short[:88]


@router.get("")
def list_workflows(org: models.Organization = Depends(auth.require_org),
                   session: Session = Depends(get_session)):
    """Everything runnable, in one list: what shipped, and what this org wrote."""
    document = surface_plan.catalog()
    system = [_system_data(name, profile)
              for name, profile in sorted(document.get("profiles", {}).items())]
    mine = [_row_data(row) for row in
            (session.query(models.ScanWorkflow)
             .filter_by(org_id=org.id, archived=False)
             .order_by(models.ScanWorkflow.created_at).all())]
    return {"system": system, "mine": mine,
            "rules": surface_plan.rules(),
            "catalog_hash": surface_plan.catalog_hash()}


@router.get("/tools")
def list_tools(org: models.Organization = Depends(auth.require_org)):
    """The arsenal, for the editor: a step can only name what exists."""
    document = surface_plan.catalog()
    rows = [{"name": name, "purpose": tool.get("purpose"),
             "kind": tool.get("kind"), "runs": tool.get("runs"),
             "targets": tool.get("targets") or [], "capability": tool.get("capability"),
             "level": tool.get("level"), "image": tool.get("image"),
             "needs": tool.get("needs") or [], "produces": tool.get("produces"),
             "when": tool.get("when"), "noise": (tool.get("cost") or {}).get("noise")}
            for name, tool in sorted(document.get("tools", {}).items())]
    return {"tools": rows, "rules": surface_plan.rules()}


@router.post("", status_code=status.HTTP_201_CREATED)
def create_workflow(payload: WorkflowIn = None,
                    org: models.Organization = Depends(auth.require_admin),
                    session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    document = payload.model_dump()
    if payload.clone_from:
        # Cloning starts from the engine's copy; anything the caller sent wins,
        # so "clone and change one stage" is one request instead of two.
        base = surface_workflow.from_catalog(payload.clone_from)
        base.update({key: value for key, value in document.items()
                     if value not in (None, [], {}, "")})
        base["name"] = payload.clone_from
        document = base
    document["stages"] = [stage.model_dump(by_alias=True) for stage in payload.stages] \
        if payload.stages else document.get("stages") or []

    slug = _slug_for(payload)
    try:
        normalized = surface_workflow.normalize(document, slug=slug)
    except surface_workflow.WorkflowError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            error.payload()) from None
    if (session.query(models.ScanWorkflow)
            .filter_by(org_id=org.id, slug=slug).first() is not None):
        raise HTTPException(status.HTTP_409_CONFLICT,
                            {"code": "workflow.slug_taken", "at": slug})

    row = models.ScanWorkflow(
        org_id=org.id, slug=slug, label=normalized["label"],
        question=normalized["question"], target_kind=normalized["target_kind"],
        level=normalized["level"], plane=json.dumps(normalized["plane"]),
        stages=json.dumps(normalized["stages"]), limits=json.dumps(normalized["limits"]),
        cloned_from=payload.clone_from, created_by=payload.actor,
    )
    session.add(row)
    session.flush()
    _audit_log(session, org.id, payload.actor, "workflow.created", "scan_workflow",
               row.id, f"{row.slug} · {row.level} · {len(normalized['stages'])} stage(s)")
    session.commit()
    return {"data": _row_data(row)}


@router.patch("/{workflow_id}")
def patch_workflow(workflow_id: str, payload: WorkflowPatch = None,
                   org: models.Organization = Depends(auth.require_admin),
                   session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    row = (session.query(models.ScanWorkflow)
           .filter_by(id=workflow_id, org_id=org.id).first())
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown workflow")

    document = surface_workflow.document_for(row)
    if payload.label is not None:
        document["label"] = payload.label
    if payload.question is not None:
        document["question"] = payload.question
    if payload.level is not None:
        document["level"] = payload.level
    if payload.plane is not None:
        document["plane"] = payload.plane
    if payload.stages is not None:
        document["stages"] = [stage.model_dump(by_alias=True) for stage in payload.stages]
    if payload.limits is not None:
        document["limits"] = payload.limits

    try:
        normalized = surface_workflow.normalize(document, slug=row.slug)
    except surface_workflow.WorkflowError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            error.payload()) from None

    row.label = normalized["label"]
    row.question = normalized["question"]
    row.target_kind = normalized["target_kind"]
    row.level = normalized["level"]
    row.plane = json.dumps(normalized["plane"])
    row.stages = json.dumps(normalized["stages"])
    row.limits = json.dumps(normalized["limits"])
    _audit_log(session, org.id, payload.actor, "workflow.updated", "scan_workflow",
               row.id, f"{row.slug} · {row.level} · {len(normalized['stages'])} stage(s)")
    session.commit()
    return {"data": _row_data(row)}


@router.delete("/{workflow_id}")
def archive_workflow(workflow_id: str, actor: str = "console",
                     org: models.Organization = Depends(auth.require_admin),
                     session: Session = Depends(get_session)):
    """Archive, never delete: a plan that ran is a record that names this slug."""
    row = (session.query(models.ScanWorkflow)
           .filter_by(id=workflow_id, org_id=org.id).first())
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown workflow")
    row.archived = True
    _audit_log(session, org.id, actor, "workflow.archived", "scan_workflow",
               row.id, row.slug)
    session.commit()
    return {"data": _row_data(row)}

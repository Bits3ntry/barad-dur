"""Resolve a project reference from a screen or API call.

The console historically sent the project *name* while the API filters by slug.
Both are legitimate identifiers for a reader, so one helper accepts either and
every route that takes `?project=` uses it instead of assuming the slug.
"""
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app import models


def by_ref(session: Session, org_id: str, ref: str | None):
    if not ref:
        return None
    # Three refs, one answer. Every screen and every agent holds the **id** — it is what
    # the inventory returns — and resolving only by slug meant `?project=<id>` answered
    # "project not found" for a project the operator could see. A resolver that refuses
    # the identifier its own API hands out is a resolver that lies.
    row = session.get(models.Project, ref)
    if row is not None and row.org_id == org_id:
        return row
    row = (session.query(models.Project)
           .filter_by(org_id=org_id, slug=ref).one_or_none())
    if row is not None:
        return row
    return (session.query(models.Project)
            .filter_by(org_id=org_id)
            .filter(func.lower(models.Project.name) == ref.strip().lower())
            .one_or_none())

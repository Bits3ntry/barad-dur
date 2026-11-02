"""Resolve a project reference from a screen or API call.

The console historically sent the project *name* while the API filters by slug.
Both are legitimate identifiers for a reader, so one helper accepts either and
every route that takes `?project=` uses it instead of assuming the slug.
"""
from sqlalchemy.orm import Session

from backend.app import models


def by_ref(session: Session, org_id: str, ref: str | None):
    if not ref:
        return None
    row = (session.query(models.Project)
           .filter_by(org_id=org_id, slug=ref).one_or_none())
    if row is not None:
        return row
    return (session.query(models.Project)
            .filter_by(org_id=org_id, name=ref).one_or_none())

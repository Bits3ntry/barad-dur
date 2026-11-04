"""Version lookup shared by the endpoints that speak in labels.

A version belongs to a component, so `AUREA 1.8` can exist twice: once for the
backend and once for the web. Endpoints that only receive a label (dashboards,
findings, licences, gates…) resolve it here, deterministically:

1. the requested component, when one is given;
2. otherwise a product-wide release with that label;
3. otherwise the oldest row, so a legacy caller keeps a stable answer.

Aliasing a duplicate label into one row is never silent in the UI: the project
screen always passes `component_id`.
"""
from sqlalchemy.orm import Session

from backend.app import models


def pick_version(session: Session, project_id: str, version: str | None,
                 component_id: str | None = None) -> models.ProjectVersion | None:
    if not version:
        return None
    query = (session.query(models.ProjectVersion)
             .filter_by(project_id=project_id, version=version))
    if component_id:
        return query.filter_by(component_id=component_id).one_or_none()
    rows = (query
            .order_by(models.ProjectVersion.component_id.is_(None).desc(),
                      models.ProjectVersion.created_at)
            .all())
    return rows[0] if rows else None

"""Walking the estate: neighbours, paths and blast radius.

One derived edge table, three questions. The console asks them when it opens an
object: "what does this finding touch?" is the same traversal whether the object is a
finding, an asset, a package or a cycle.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app import auth, graph, models
from backend.app.db import get_session

router = APIRouter(prefix="/api/v1/graph", tags=["graph"])

#: Types whose table carries `org_id`. The others are catalogue rows shared by every
#: tenant (packages, advisories) and are reachable, not owned.
_ORG_SCOPED = {"projects", "assets", "findings", "application_components",
               "project_versions", "cycles", "work_items", "deployments", "users",
               "scan_jobs", "occurrences"}


def _ensure_edges(session: Session) -> None:
    """An empty projection is a cold cache, not a graph with no relations."""
    count = session.execute(text("SELECT count(*) FROM graph_edges")).scalar_one()
    if count == 0:
        graph.rebuild(session)


def _assert_visible(session: Session, node_type: str, node_id: str,
                    org: models.Organization) -> None:
    source = graph.LABEL_SOURCES.get(node_type)
    if source is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"unknown node type '{node_type}'")
    table = source[0]
    if table not in _ORG_SCOPED:
        return
    rows = session.execute(text(
        f"SELECT 1 FROM {table} WHERE id::text = :id AND org_id = :org"
    ), {"id": node_id, "org": org.id}).first()
    if rows is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "node not found")


@router.get("/neighbors")
def graph_neighbors(node_type: str = Query(alias="type", min_length=1, max_length=48),
                    node_id: str = Query(alias="id", min_length=1, max_length=64),
                    depth: int = Query(default=2, ge=1, le=4),
                    org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    """Everything within `depth` hops, with the edge that reached it."""
    _assert_visible(session, node_type, node_id, org)
    _ensure_edges(session)
    return {"data": graph.neighbors(session, node_type, node_id, depth)}


@router.get("/kinds")
def graph_kinds(org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    """Which relations the projection knows — the legend of the graph."""
    rows = session.execute(text(
        "SELECT rel, src_type, dst_type, count(*) AS n FROM graph_edges "
        "GROUP BY rel, src_type, dst_type ORDER BY n DESC"
    )).all()
    return {"data": [{"rel": rel, "from": src, "to": dst, "edges": n}
                     for rel, src, dst, n in rows]}


@router.post("/rebuild")
def graph_rebuild(org: models.Organization = Depends(auth.require_admin),
                  session: Session = Depends(get_session)):
    """Recompute the projection from the catalogue. Safe to call any time."""
    return {"data": graph.rebuild(session)}

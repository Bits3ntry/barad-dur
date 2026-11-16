"""The estate as a graph, derived — never authored.

The relations already exist: 222 foreign keys plus five bridge tables say how a
finding reaches a deployment, a version, a package, an advisory, a project. What was
missing is the ability to *walk* them without hand-writing a join per question, so
every multi-hop answer was bespoke SQL or, worse, never asked.

`graph_edges` is that same graph flattened and refreshed from the catalogue. It is a
projection: the schema stays the source of truth, and the table can be rebuilt at any
moment with no data loss.

Why not a graph database: at this size (thousands of edges) a recursive CTE over one
indexed table answers in milliseconds, keeps the foreign keys enforced, and adds no
second system to operate. The day the edge count or the hop depth outgrows that, the
shape of this module is exactly what you would feed to Kuzu or AGE.
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app import models

#: One vocabulary for node types: a table is a *set* of nodes, the graph speaks of
#: one of them. Without this the foreign keys spoke table names (`findings`) and the
#: bridges spoke singular ones (`finding`), so a walk started in one dialect and
#: never met the other.
TYPE_OF_TABLE: dict[str, str] = {
    "projects": "project",
    "assets": "asset",
    "findings": "finding",
    "components": "component",
    "application_components": "application_component",
    "project_versions": "project_version",
    "cycles": "cycle",
    "work_items": "work_item",
    "deployments": "deployment",
    "users": "user",
    "vulnerabilities": "vulnerability",
    "scan_jobs": "scan_job",
    "occurrences": "occurrence",
    "organizations": "organization",
    "services": "service",
    "artifacts": "artifact",
    "repositories": "repository",
    "agent_missions": "agent_mission",
    "agent_tasks": "agent_task",
}


def _type_of(table: str) -> str:
    return TYPE_OF_TABLE.get(table, table)


#: Which attribute gives a node a name a person can read. A type absent here is
#: still traversable; it just shows its id.
LABEL_SOURCES: dict[str, tuple[str, str]] = {
    "project": ("projects", "name"),
    "asset": ("assets", "value"),
    "finding": ("findings", "title"),
    "component": ("components", "name"),
    "application_component": ("application_components", "name"),
    "project_version": ("project_versions", "version"),
    "cycle": ("cycles", "name"),
    "work_item": ("work_items", "title"),
    "deployment": ("deployments", "name"),
    "user": ("users", "email"),
    "vulnerability": ("vulnerabilities", "id"),
    "scan_job": ("scan_jobs", "id"),
    "occurrence": ("occurrences", "id"),
    "organization": ("organizations", "name"),
    "service": ("services", "name"),
    "artifact": ("artifacts", "id"),
    "repository": ("repositories", "remote_url"),
    "agent_mission": ("agent_missions", "goal"),
    "agent_task": ("agent_tasks", "kind"),
}

_FK_QUERY = text("""
    SELECT tc.table_name AS child,
           kcu.column_name AS column_name,
           ccu.table_name  AS parent
      FROM information_schema.table_constraints tc
      JOIN information_schema.key_column_usage kcu
        ON kcu.constraint_name = tc.constraint_name
       AND kcu.table_schema = tc.table_schema
      JOIN information_schema.constraint_column_usage ccu
        ON ccu.constraint_name = tc.constraint_name
       AND ccu.table_schema = tc.table_schema
     WHERE tc.constraint_type = 'FOREIGN KEY'
       AND tc.table_schema = 'public'
       AND tc.table_name <> 'graph_edges'
     ORDER BY tc.table_name, kcu.column_name
""")


#: Ownership is not a relation. Every row in the estate points at its organization,
#: so keeping those edges makes the organization a hub joined to everything: a walk of
#: depth 2 from any finding returned the whole tenant (6.269 nodes). The tenant is the
#: frame of the walk, not a hop in it.
_OWNERSHIP_COLUMNS = {"org_id"}

#: A panel shows a neighbourhood, not a dump: past this the answer is "narrow it".
LIMIT = 300

#: Join tables are edges wearing a table's clothes. Their meaning is already stated by
#: `graph_bridges` ("this cycle holds that finding"), and keeping their own foreign
#: keys turned every row into a node called `cycle_findings`.
_BRIDGE_TABLES = {"cycle_findings", "asset_links", "version_components",
                  "scan_grant_targets", "cycle_memberships"}


def rebuild(session: Session) -> dict:
    """Recompute every edge from the catalogue. Idempotent and cheap."""
    session.execute(text("DELETE FROM graph_edges"))
    foreign_keys = [row for row in session.execute(_FK_QUERY).all()
                    if row.column_name not in _OWNERSHIP_COLUMNS
                    and row.child not in _BRIDGE_TABLES]
    inserted = 0
    for child, column, parent in foreign_keys:
        src, dst = _type_of(child), _type_of(parent)
        result = session.execute(text(f"""
            INSERT INTO graph_edges (id, src_type, src_id, rel, dst_type, dst_id)
            SELECT '{src}:{column}:' || id::text, '{src}', id::text, '{column}',
                   '{dst}', {column}::text
              FROM {child}
             WHERE {column} IS NOT NULL
            ON CONFLICT (id) DO NOTHING
        """))
        inserted += result.rowcount or 0
    # Bridges: a relation with no column named after its target.
    bridges = session.execute(text("""
        INSERT INTO graph_edges (id, src_type, src_id, rel, dst_type, dst_id)
        SELECT 'bridge:' || src_type || ':' || src_id || ':' || rel || ':' || dst_id,
               src_type, src_id, rel, dst_type, dst_id
          FROM graph_bridges
        ON CONFLICT (id) DO NOTHING
    """))
    inserted += bridges.rowcount or 0
    session.commit()
    total = session.execute(text("SELECT count(*) FROM graph_edges")).scalar_one()
    return {"edges": total, "relations": len(foreign_keys) + 4}


def _labels(session: Session, nodes: set[tuple[str, str]]) -> dict[tuple[str, str], str]:
    """One query per type present, never one per node."""
    labels: dict[tuple[str, str], str] = {}
    by_type: dict[str, list[str]] = {}
    for node_type, node_id in nodes:
        by_type.setdefault(node_type, []).append(node_id)
    for node_type, ids in by_type.items():
        source = LABEL_SOURCES.get(node_type)
        if not source:
            continue
        table, column = source
        try:
            rows = session.execute(text(
                f"SELECT id::text, {column}::text FROM {table} WHERE id::text = ANY(:ids)"
            ), {"ids": ids}).all()
        except Exception:                       # a guessed column, a dropped table
            session.rollback()
            continue
        for node_id, label in rows:
            labels[(node_type, node_id)] = label or node_id
    return labels


def _routes(session: Session, nodes: set[tuple[str, str]]) -> dict[tuple[str, str], str]:
    """Where the console can open that node. A graph you cannot walk to is a picture."""
    routes: dict[tuple[str, str], str] = {}
    for node_type, node_id in nodes:
        if node_type == "finding":
            routes[(node_type, node_id)] = f"#findings::{node_id}"
        elif node_type == "cycle":
            routes[(node_type, node_id)] = f"#cycles::{node_id}"
        elif node_type == "asset":
            routes[(node_type, node_id)] = f"#asset::{node_id}"
        elif node_type == "component":
            routes[(node_type, node_id)] = f"#component::{node_id}"
        elif node_type == "work_item":
            routes[(node_type, node_id)] = "#my-work"
    project_ids = [node_id for node_type, node_id in nodes if node_type == "project"]
    if project_ids:
        rows = session.execute(text(
            "SELECT id::text, slug FROM projects WHERE id::text = ANY(:ids)"
        ), {"ids": project_ids}).all()
        for project_id, slug in rows:
            routes[("project", project_id)] = f"/projects/{slug}"
    return routes


def neighbors(session: Session, node_type: str, node_id: str, depth: int = 2) -> dict:
    """Everything within `depth` hops of one node, with the edges that connect it."""
    rows = session.execute(text("""
        WITH RECURSIVE walk(depth, type, id, rel, parent_type, parent_id) AS (
            SELECT 0, CAST(:type AS text), CAST(:id AS text),
                   CAST(NULL AS text), CAST(NULL AS text), CAST(NULL AS text)
          UNION
            SELECT w.depth + 1,
                   CASE WHEN e.src_type = w.type AND e.src_id = w.id
                        THEN e.dst_type ELSE e.src_type END,
                   CASE WHEN e.src_type = w.type AND e.src_id = w.id
                        THEN e.dst_id ELSE e.src_id END,
                   e.rel, w.type, w.id
              FROM walk w
              JOIN graph_edges e
                ON (e.src_type = w.type AND e.src_id = w.id)
                OR (e.dst_type = w.type AND e.dst_id = w.id)
             WHERE w.depth < :depth
        )
        SELECT depth, type, id, rel, parent_type, parent_id
          FROM walk
         WHERE depth > 0
    """), {"type": node_type, "id": node_id, "depth": depth}).all()

    # Shortest hop wins: a node reachable at 1 and at 3 is a neighbour, not a rumour.
    best: dict[tuple[str, str], dict] = {}
    for depth_seen, row_type, row_id, rel, parent_type, parent_id in rows:
        key = (row_type, row_id)
        current = best.get(key)
        if current is None or depth_seen < current["depth"]:
            best[key] = {"type": row_type, "id": row_id, "depth": depth_seen,
                         "rel": rel, "from": {"type": parent_type, "id": parent_id}}
    ordered = sorted(best.items(), key=lambda item: (item[1]["depth"], item[0]))
    truncated = len(ordered) > LIMIT
    ordered = ordered[:LIMIT]
    best = dict(ordered)
    scope = set(best) | {(node_type, node_id)}
    labels = _labels(session, scope)
    routes = _routes(session, scope)
    nodes = [{"type": node_type, "id": node_id, "depth": 0,
              "label": labels.get((node_type, node_id), node_id),
              "route": routes.get((node_type, node_id))}]
    for key, node in ordered:
        nodes.append({**node, "label": labels.get(key, node["id"]),
                      "route": routes.get(key)})
    return {
        "root": {"type": node_type, "id": node_id},
        "nodes": nodes,
        "edges": [{"from": node["from"], "to": {"type": node["type"], "id": node["id"]},
                   "rel": node["rel"], "depth": node["depth"]}
                  for node in nodes if node["depth"] > 0],
        "truncated": truncated,
        "by_depth": {level: sum(1 for node in nodes if node["depth"] == level)
                     for level in range(depth + 1)},
    }

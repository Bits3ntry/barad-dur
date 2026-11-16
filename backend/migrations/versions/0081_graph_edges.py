"""a derived edge table, so relations are one query instead of five joins

The platform already states its relations 222 times in foreign keys. What it could
not do is *walk* them: every multi-hop question ("what does this finding reach?")
was hand-written SQL. This table is that same graph, flattened, refreshed from the
catalogue — derived, never authored, so it cannot disagree with the schema.

Revision ID: 0081_graph_edges
Revises: 0080_agent_findings
Create Date: 2026-11-13
"""

from alembic import op
import sqlalchemy as sa


revision = "0081_graph_edges"
down_revision = "0080_agent_findings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "graph_edges",
        sa.Column("id", sa.String(64), primary_key=True),
        #: The table the row lives in: `findings`, `deployments`, `project_versions`…
        sa.Column("src_type", sa.String(48), nullable=False),
        sa.Column("src_id", sa.String(64), nullable=False),
        #: The column that points: `project_id`, `component_id`, `finding_id`…
        sa.Column("rel", sa.String(64), nullable=False),
        sa.Column("dst_type", sa.String(48), nullable=False),
        sa.Column("dst_id", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_graph_edges_src", "graph_edges", ["src_type", "src_id"])
    op.create_index("ix_graph_edges_dst", "graph_edges", ["dst_type", "dst_id"])
    op.create_index("ix_graph_edges_rel", "graph_edges", ["rel"])

    # Bridge tables are relations too, and they do not look like foreign keys from
    # the walker's side: an asset_link says "this asset serves that deployment"
    # without a column named after the target.
    op.execute("""
        CREATE OR REPLACE VIEW graph_bridges AS
        SELECT 'asset' AS src_type, asset_id AS src_id, 'serves' AS rel,
               entity_type AS dst_type, entity_id AS dst_id
          FROM asset_links
        UNION ALL
        SELECT 'cycle', cycle_id, 'ledger', 'finding', finding_id
          FROM cycle_findings
        UNION ALL
        SELECT 'project_version', project_version_id, 'ships', 'component', component_id
          FROM version_components
        UNION ALL
        SELECT 'work_item', id, 'works_on', 'finding', finding_id
          FROM work_items WHERE finding_id IS NOT NULL
    """)


def downgrade() -> None:
    op.execute("DROP VIEW IF EXISTS graph_bridges")
    op.drop_index("ix_graph_edges_rel", table_name="graph_edges")
    op.drop_index("ix_graph_edges_dst", table_name="graph_edges")
    op.drop_index("ix_graph_edges_src", table_name="graph_edges")
    op.drop_table("graph_edges")

"""edge ids need room: table + column + uuid is longer than 64

The projection's primary key is `{table}:{column}:{id}`, which for a real relation
("analysis_runs:project_version_id:<uuid>") is 62+ characters before the id is even
counted. 64 was a guess; the walker found it on the first rebuild.

Revision ID: 0082_graph_edge_id_width
Revises: 0081_graph_edges
Create Date: 2026-11-13
"""

from alembic import op
import sqlalchemy as sa


revision = "0082_graph_edge_id_width"
down_revision = "0081_graph_edges"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("graph_edges", "id", type_=sa.Text(), existing_nullable=False)


def downgrade() -> None:
    op.alter_column("graph_edges", "id", type_=sa.String(64), existing_nullable=False)

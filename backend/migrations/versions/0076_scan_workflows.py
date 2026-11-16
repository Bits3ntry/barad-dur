"""scan_workflows: an organisation's own profile, in the catalog's shape

A workflow written in the console is a document — stages, limits, level — that the
resolver plans exactly like a catalog profile. Storing it as rows per stage would
have bought nothing: nothing queries a stage alone.

Revision ID: 0076_scan_workflows
Revises: 0075_ai_metrics
Create Date: 2026-11-10
"""

from alembic import op
import sqlalchemy as sa


revision = "0076_scan_workflows"
down_revision = "0075_ai_metrics"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_workflows",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"),
                  nullable=False),
        sa.Column("slug", sa.String(96), nullable=False),
        sa.Column("label", sa.String(128), nullable=False),
        sa.Column("question", sa.Text(), nullable=False, server_default=""),
        sa.Column("target_kind", sa.String(32), nullable=False, server_default="domain"),
        sa.Column("level", sa.String(16), nullable=False, server_default="simple"),
        sa.Column("plane", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("stages", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("limits", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("cloned_from", sa.String(96), nullable=True),
        sa.Column("created_by", sa.String(255), nullable=False, server_default="console"),
        sa.Column("archived", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "slug", name="uq_workflows_org_slug"),
    )
    op.create_index("ix_workflows_org", "scan_workflows", ["org_id"])


def downgrade() -> None:
    op.drop_index("ix_workflows_org", table_name="scan_workflows")
    op.drop_table("scan_workflows")

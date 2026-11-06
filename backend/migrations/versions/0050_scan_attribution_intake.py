"""store scans that need human component attribution

Revision ID: 0050_scan_attribution_intake
Revises: 0049_finding_vectors
Create Date: 2026-11-05
"""

from alembic import op
import sqlalchemy as sa


revision = "0050_scan_attribution_intake"
down_revision = "0049_finding_vectors"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_attribution_intakes",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("org_id", sa.String(length=36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("project_id", sa.String(length=36), sa.ForeignKey("projects.id"), nullable=True),
        sa.Column("repository_id", sa.String(length=36), sa.ForeignKey("repositories.id"), nullable=True),
        sa.Column("status", sa.String(length=24), nullable=False, server_default="needs_attribution"),
        sa.Column("reason", sa.String(length=128), nullable=False),
        sa.Column("subject", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("candidate_component_ids", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("created_by", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("assigned_by", sa.String(length=255), nullable=True),
        sa.Column("assignment_note", sa.Text(), nullable=True),
    )
    op.create_index("ix_scan_attribution_intakes_org_id", "scan_attribution_intakes", ["org_id"])
    op.create_index("ix_scan_attribution_intakes_status", "scan_attribution_intakes", ["status"])


def downgrade() -> None:
    op.drop_index("ix_scan_attribution_intakes_status", table_name="scan_attribution_intakes")
    op.drop_index("ix_scan_attribution_intakes_org_id", table_name="scan_attribution_intakes")
    op.drop_table("scan_attribution_intakes")

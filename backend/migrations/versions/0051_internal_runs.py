"""record the runs of platform-owned jobs (the advisory clock)

Revision ID: 0051_internal_runs
Revises: 0050_scan_attribution_intake
Create Date: 2026-11-06
"""

from alembic import op
import sqlalchemy as sa


revision = "0051_internal_runs"
down_revision = "0050_scan_attribution_intake"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "internal_runs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("org_id", sa.String(length=36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False, server_default="advisory-clock"),
        sa.Column("trigger", sa.String(length=16), nullable=False, server_default="schedule"),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="running"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("counters", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("log", sa.Text(), nullable=False, server_default=""),
        sa.Column("actor", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_internal_runs_org_id", "internal_runs", ["org_id"])
    op.create_index("ix_internal_runs_org_name", "internal_runs", ["org_id", "name"])


def downgrade() -> None:
    op.drop_index("ix_internal_runs_org_name", table_name="internal_runs")
    op.drop_index("ix_internal_runs_org_id", table_name="internal_runs")
    op.drop_table("internal_runs")

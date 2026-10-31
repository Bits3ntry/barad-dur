"""Scheduling of scan jobs.

Revision ID: 0023_schedules
Revises: 0022_auth
Create Date: 2026-10-31
"""
from alembic import op
import sqlalchemy as sa

revision = "0023_schedules"
down_revision = "0022_auth"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_schedules",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("scanner", sa.String(64), nullable=False),
        sa.Column("capability", sa.String(64), nullable=False),
        sa.Column("principal", sa.String(255), nullable=False),
        sa.Column("targets", sa.Text, nullable=False, default="[]"),
        sa.Column("environment", sa.String(128), nullable=True),
        sa.Column("profile", sa.Text, nullable=False, default="{}"),
        sa.Column("interval_minutes", sa.Integer, nullable=False, default=1440),
        sa.Column("enabled", sa.Boolean, nullable=False, default=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_job_id", sa.String(36), nullable=True),
        sa.Column("last_error", sa.Text, nullable=True),
        sa.Column("created_by", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "name", name="uq_schedules_org_name"),
    )
    op.create_index("ix_schedules_due", "scan_schedules", ["org_id", "next_run_at"])


def downgrade() -> None:
    op.drop_index("ix_schedules_due", table_name="scan_schedules")
    op.drop_table("scan_schedules")

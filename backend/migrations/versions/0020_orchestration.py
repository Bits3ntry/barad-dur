"""BL-020: scanner registry, workers, leased jobs and artifacts.

Revision ID: 0020_orchestration
Revises: 0019_regression
Create Date: 2026-10-31
"""
from alembic import op
import sqlalchemy as sa

revision = "0020_orchestration"
down_revision = "0019_regression"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scanners",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("display_name", sa.String(128), nullable=False),
        sa.Column("capability", sa.String(64), nullable=False),
        sa.Column("version", sa.String(64), nullable=True),
        sa.Column("adapter", sa.String(64), nullable=False, default="cli"),
        sa.Column("enabled", sa.Boolean, nullable=False, default=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "name", name="uq_scanners_org_name"),
    )
    op.create_table(
        "workers",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("capabilities", sa.Text, nullable=False, default="[]"),
        sa.Column("labels", sa.Text, nullable=False, default="{}"),
        sa.Column("max_concurrent", sa.Integer, nullable=False, default=1),
        sa.Column("status", sa.String(16), nullable=False, default="online"),
        sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_heartbeat", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "name", name="uq_workers_org_name"),
    )
    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("project_version_id", sa.String(36),
                  sa.ForeignKey("project_versions.id"), nullable=True),
        sa.Column("scanner", sa.String(64), nullable=False),
        sa.Column("capability", sa.String(64), nullable=False),
        sa.Column("principal", sa.String(255), nullable=False),
        sa.Column("environment", sa.String(128), nullable=True),
        sa.Column("targets", sa.Text, nullable=False, default="[]"),
        sa.Column("profile", sa.Text, nullable=False, default="{}"),
        sa.Column("status", sa.String(16), nullable=False, default="queued"),
        sa.Column("priority", sa.Integer, nullable=False, default=5),
        sa.Column("attempts", sa.Integer, nullable=False, default=0),
        sa.Column("max_attempts", sa.Integer, nullable=False, default=3),
        sa.Column("worker_id", sa.String(36), sa.ForeignKey("workers.id"), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("authorization", sa.Text, nullable=True),
        sa.Column("result", sa.Text, nullable=True),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("created_by", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_scan_jobs_status", "scan_jobs", ["org_id", "status"])
    op.create_table(
        "job_artifacts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("job_id", sa.String(36),
                  sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("job_artifacts")
    op.drop_index("ix_scan_jobs_status", table_name="scan_jobs")
    op.drop_table("scan_jobs")
    op.drop_table("workers")
    op.drop_table("scanners")

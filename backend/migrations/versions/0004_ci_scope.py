"""F3: CI pipeline/run registry with gate verdicts and static scope model.

Revision ID: 0004_ci_scope
Revises: 0003_suppressions
Create Date: 2026-10-30
"""
from alembic import op
import sqlalchemy as sa

revision = "0004_ci_scope"
down_revision = "0003_suppressions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ci_pipelines",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False, default="github"),
        sa.Column("repository", sa.String(512), nullable=False),
        sa.Column("workflow_path", sa.String(512), nullable=True),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "provider", "repository", "workflow_path",
                            name="uq_ci_pipelines_identity"),
    )
    op.create_table(
        "ci_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("pipeline_id", sa.String(36), sa.ForeignKey("ci_pipelines.id"), nullable=True),
        sa.Column("ref", sa.String(512), nullable=True),
        sa.Column("commit_sha", sa.String(64), nullable=True),
        sa.Column("event", sa.String(64), nullable=True),
        sa.Column("actor", sa.String(255), nullable=True),
        sa.Column("status", sa.String(32), nullable=False, default="running"),
        sa.Column("verdict", sa.String(32), nullable=True),
        sa.Column("verdict_detail", sa.Text, nullable=True),
        sa.Column("findings_count", sa.Integer, nullable=False, default=0),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_ci_runs_org", "ci_runs", ["org_id"])
    op.create_table(
        "ci_run_findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("run_id", sa.String(36), sa.ForeignKey("ci_runs.id"), nullable=False),
        sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("severity", sa.String(32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("run_id", "finding_id", name="uq_ci_run_findings_pair"),
    )
    op.create_table(
        "scope_targets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=False),
        sa.Column("value", sa.String(1024), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, default="active"),
        sa.Column("note", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "target_type", "value", name="uq_scope_targets_identity"),
    )
    op.create_table(
        "scope_exclusions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=False),
        sa.Column("value", sa.String(1024), nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "target_type", "value", name="uq_scope_exclusions_identity"),
    )


def downgrade() -> None:
    op.drop_table("scope_exclusions")
    op.drop_table("scope_targets")
    op.drop_table("ci_run_findings")
    op.drop_table("ci_runs")
    op.drop_table("ci_pipelines")

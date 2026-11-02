"""Migration 0035: analysis runs and what they evaluated.

A finding may only be closed by an analysis that actually covered it. This
migration adds the run record (tool, revision, coverage) and the pointer from a
finding to the last run that evaluated it. Additive; existing findings keep
`last_evaluated_run_id = NULL`, which reads as "never evaluated by a recorded
run" — exactly the honest state.
"""
from alembic import op
import sqlalchemy as sa

revision = "0035_analysis_runs"
down_revision = "0034_scope_targets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "analysis_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("project_version_id", sa.String(36),
                  sa.ForeignKey("project_versions.id"), nullable=True),
        sa.Column("tool", sa.String(64), nullable=False),
        sa.Column("tool_version", sa.String(64), nullable=True),
        sa.Column("coverage", sa.String(16), nullable=False, server_default="unknown"),
        sa.Column("source", sa.String(32), nullable=False, server_default="import"),
        sa.Column("revision", sa.String(128), nullable=True),
        sa.Column("branch", sa.String(255), nullable=True),
        sa.Column("base_revision", sa.String(128), nullable=True),
        sa.Column("evaluated", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("receipt", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("findings_seen", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("actor", sa.String(255), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_analysis_runs_org", "analysis_runs", ["org_id"])
    op.create_index("ix_analysis_runs_project", "analysis_runs",
                    ["project_id", "project_version_id"])

    op.add_column("findings", sa.Column("last_evaluated_run_id", sa.String(36), nullable=True))
    op.create_index("ix_findings_last_evaluated_run", "findings", ["last_evaluated_run_id"])


def downgrade() -> None:
    op.drop_index("ix_findings_last_evaluated_run", table_name="findings")
    op.drop_column("findings", "last_evaluated_run_id")
    op.drop_index("ix_analysis_runs_project", table_name="analysis_runs")
    op.drop_index("ix_analysis_runs_org", table_name="analysis_runs")
    op.drop_table("analysis_runs")

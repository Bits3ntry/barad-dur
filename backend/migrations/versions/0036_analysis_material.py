"""Migration 0036: SAST analysis material — files, classified results, diff.

An analysis run keeps the code it can show (`analysis_files`) and one row per
result with its classification against a comparable baseline. New/persistent/
resolved only exist when a base run of the same tool is supplied; otherwise the
row says `no_reference`, which is not the same statement as `new`.
"""
from alembic import op
import sqlalchemy as sa

revision = "0036_analysis_material"
down_revision = "0035_analysis_runs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("analysis_runs", sa.Column("base_run_id", sa.String(36), nullable=True))
    op.add_column("analysis_runs", sa.Column("report_format", sa.String(16), nullable=True))
    op.add_column("analysis_runs", sa.Column("rules", sa.JSON(), nullable=False,
                                             server_default="[]"))
    op.add_column("analysis_runs", sa.Column("uninterpreted", sa.JSON(), nullable=False,
                                             server_default="{}"))
    op.add_column("analysis_runs", sa.Column("diff_text", sa.Text(), nullable=True))

    op.create_table(
        "analysis_files",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("run_id", sa.String(36),
                  sa.ForeignKey("analysis_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("path", sa.String(1024), nullable=False),
        sa.Column("content", sa.Text(), nullable=True),
        sa.Column("content_hash", sa.String(64), nullable=True),
        sa.Column("line_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("kind", sa.String(16), nullable=False, server_default="analyzed"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("run_id", "path", name="uq_analysis_file_path"),
    )
    op.create_index("ix_analysis_files_org", "analysis_files", ["org_id"])
    op.create_index("ix_analysis_files_run", "analysis_files", ["run_id"])

    op.create_table(
        "analysis_findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("run_id", sa.String(36),
                  sa.ForeignKey("analysis_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_id", sa.String(36),
                  sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("path", sa.String(1024), nullable=False),
        sa.Column("line", sa.Integer(), nullable=True),
        sa.Column("end_line", sa.Integer(), nullable=True),
        sa.Column("rule_id", sa.String(512), nullable=True),
        sa.Column("severity", sa.String(32), nullable=True),
        sa.Column("cwe", sa.String(64), nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("snippet", sa.Text(), nullable=True),
        sa.Column("classification", sa.String(24), nullable=False,
                  server_default="no_reference"),
        sa.Column("on_modified_line", sa.Boolean(), nullable=False,
                  server_default=sa.false()),
        sa.Column("introduced_by_pr", sa.Boolean(), nullable=False,
                  server_default=sa.false()),
        sa.Column("source_sink", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("run_id", "finding_id", "line",
                            name="uq_analysis_finding_line"),
    )
    op.create_index("ix_analysis_findings_org", "analysis_findings", ["org_id"])
    op.create_index("ix_analysis_findings_run", "analysis_findings", ["run_id"])
    op.create_index("ix_analysis_findings_finding", "analysis_findings", ["finding_id"])


def downgrade() -> None:
    op.drop_index("ix_analysis_findings_finding", table_name="analysis_findings")
    op.drop_index("ix_analysis_findings_run", table_name="analysis_findings")
    op.drop_index("ix_analysis_findings_org", table_name="analysis_findings")
    op.drop_table("analysis_findings")
    op.drop_index("ix_analysis_files_run", table_name="analysis_files")
    op.drop_index("ix_analysis_files_org", table_name="analysis_files")
    op.drop_table("analysis_files")
    op.drop_column("analysis_runs", "diff_text")
    op.drop_column("analysis_runs", "uninterpreted")
    op.drop_column("analysis_runs", "rules")
    op.drop_column("analysis_runs", "report_format")
    op.drop_column("analysis_runs", "base_run_id")

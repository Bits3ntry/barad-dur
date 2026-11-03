"""BL-040b part 2: code files, PR review and source context.

Revision ID: 0021_code_review
Revises: 0020_orchestration
Create Date: 2026-10-31
"""
from alembic import op
import sqlalchemy as sa

revision = "0021_code_review"
down_revision = "0020_orchestration"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "code_files",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("repository_id", sa.String(36),
                  sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("ref", sa.String(128), nullable=False),
        sa.Column("path", sa.String(1024), nullable=False),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_code_files_lookup", "code_files",
                    ["org_id", "repository_id", "ref", "path"])
    op.create_table(
        "pull_requests",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id"), nullable=True),
        sa.Column("project_version_id", sa.String(36),
                  sa.ForeignKey("project_versions.id"), nullable=True),
        sa.Column("repository_id", sa.String(36),
                  sa.ForeignKey("repositories.id"), nullable=True),
        sa.Column("number", sa.Integer, nullable=False),
        sa.Column("title", sa.String(512), nullable=True),
        sa.Column("branch", sa.String(255), nullable=True),
        sa.Column("base_branch", sa.String(255), nullable=True),
        sa.Column("head_sha", sa.String(64), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, default="open"),
        sa.Column("gate_verdict", sa.String(16), nullable=True),
        sa.Column("gate_reason", sa.Text, nullable=True),
        sa.Column("comment", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "repository_id", "number",
                            name="uq_pr_org_repo_number"),
    )
    op.create_table(
        "pr_findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("pr_id", sa.String(36),
                  sa.ForeignKey("pull_requests.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("classification", sa.String(16), nullable=False, default="new"),
        sa.Column("file_path", sa.String(1024), nullable=True),
        sa.Column("line", sa.Integer, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("pr_id", "finding_id", name="uq_pr_finding"),
    )


def downgrade() -> None:
    op.drop_table("pr_findings")
    op.drop_table("pull_requests")
    op.drop_index("ix_code_files_lookup", table_name="code_files")
    op.drop_table("code_files")

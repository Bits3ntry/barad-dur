"""BL-080: security regression tests and their execution history.

Revision ID: 0019_regression
Revises: 0018_jira
Create Date: 2026-10-31
"""
from alembic import op
import sqlalchemy as sa

revision = "0019_regression"
down_revision = "0018_jira"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "regression_tests",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id"), nullable=True),
        sa.Column("project_version_id", sa.String(36),
                  sa.ForeignKey("project_versions.id"), nullable=True),
        sa.Column("suite", sa.String(64), nullable=False, default="default"),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("method", sa.String(16), nullable=False, default="GET"),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("headers", sa.Text, nullable=False, default="{}"),
        sa.Column("body", sa.Text, nullable=True),
        sa.Column("assertions", sa.Text, nullable=False, default="[]"),
        sa.Column("expected_outcome", sa.String(16), nullable=False, default="pass"),
        sa.Column("source_finding_id", sa.String(36),
                  sa.ForeignKey("pentest_findings.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "regression_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("test_id", sa.String(36),
                  sa.ForeignKey("regression_tests.id", ondelete="CASCADE"), nullable=False),
        sa.Column("project_version_id", sa.String(36),
                  sa.ForeignKey("project_versions.id"), nullable=True),
        sa.Column("result", sa.String(16), nullable=False),
        sa.Column("http_status", sa.Integer, nullable=True),
        sa.Column("latency_ms", sa.Integer, nullable=True),
        sa.Column("reintroduced", sa.Boolean, nullable=False, default=False),
        sa.Column("evidence", sa.Text, nullable=True),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("actor", sa.String(255), nullable=True),
        sa.Column("ran_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_regression_runs_test", "regression_runs", ["test_id"])


def downgrade() -> None:
    op.drop_index("ix_regression_runs_test", table_name="regression_runs")
    op.drop_table("regression_runs")
    op.drop_table("regression_tests")

"""BL-050: Jira links and outbox for idempotent synchronization.

Revision ID: 0018_jira
Revises: 0017_pentest
Create Date: 2026-10-31
"""
from alembic import op
import sqlalchemy as sa

revision = "0018_jira"
down_revision = "0017_pentest"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "jira_links",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("project_key", sa.String(64), nullable=False),
        sa.Column("issue_key", sa.String(64), nullable=True),
        sa.Column("issue_url", sa.String(1024), nullable=True),
        sa.Column("external_status", sa.String(64), nullable=True),
        sa.Column("external_assignee", sa.String(255), nullable=True),
        sa.Column("sync_state", sa.String(32), nullable=False, default="pending"),
        sa.Column("last_error", sa.Text, nullable=True),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_jira_links_finding", "jira_links", ["finding_id"])
    op.create_table(
        "jira_outbox",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("link_id", sa.String(36), sa.ForeignKey("jira_links.id"), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("payload", sa.Text, nullable=False),
        sa.Column("dedupe_key", sa.String(128), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, default="pending"),
        sa.Column("attempts", sa.Integer, nullable=False, default=0),
        sa.Column("last_error", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("org_id", "dedupe_key", name="uq_jira_outbox_dedupe"),
    )


def downgrade() -> None:
    op.drop_table("jira_outbox")
    op.drop_index("ix_jira_links_finding", table_name="jira_links")
    op.drop_table("jira_links")

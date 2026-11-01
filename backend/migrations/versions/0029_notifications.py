"""Notification preferences and in-app notifications.

Revision ID: 0029_notifications
Revises: 0028_sast_baselines
Create Date: 2026-11-01
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0029_notifications"
down_revision = "0028_sast_baselines"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "notifications",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("channel", sa.String(128), nullable=True),
        sa.Column("event", sa.String(128), nullable=False),
        sa.Column("count", sa.Integer, nullable=False, default=1),
        sa.Column("read", sa.Boolean, nullable=False, default=False),
        sa.Column("payload", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_notifications_org", "notifications", ["org_id"])
    op.create_index("ix_notifications_read", "notifications", ["read"])

    op.create_table(
        "notification_preferences",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("email_enabled", sa.Boolean, nullable=False, default=True),
        sa.Column("push_enabled", sa.Boolean, nullable=False, default=True),
        sa.Column("sla_breach", sa.Boolean, nullable=False, default=True),
        sa.Column("assignment", sa.Boolean, nullable=False, default=True),
        sa.Column("retest_request", sa.Boolean, nullable=False, default=True),
        sa.Column("jira_sync_error", sa.Boolean, nullable=False, default=True),
        sa.UniqueConstraint("org_id", "user_id", name="uq_prefs_org_user"),
    )


def downgrade() -> None:
    op.drop_table("notification_preferences")
    op.drop_index("ix_notifications_read", table_name="notifications")
    op.drop_index("ix_notifications_org", table_name="notifications")
    op.drop_table("notifications")

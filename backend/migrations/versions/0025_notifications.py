"""Outbound notification channels and deliveries.

Revision ID: 0025_notifications
Revises: 0024_worker_tokens
Create Date: 2026-10-31
"""
from alembic import op
import sqlalchemy as sa

revision = "0025_notifications"
down_revision = "0024_worker_tokens"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "notification_channels",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False, default="webhook"),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("secret", sa.String(255), nullable=False),
        sa.Column("events", sa.Text, nullable=False, default="[]"),
        sa.Column("enabled", sa.Boolean, nullable=False, default=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "name", name="uq_channels_org_name"),
    )
    op.create_table(
        "notification_deliveries",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("channel_id", sa.String(36),
                  sa.ForeignKey("notification_channels.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event", sa.String(64), nullable=False),
        sa.Column("dedupe_key", sa.String(128), nullable=False),
        sa.Column("payload", sa.Text, nullable=False),
        sa.Column("status", sa.String(16), nullable=False, default="pending"),
        sa.Column("http_status", sa.Integer, nullable=True),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "dedupe_key", name="uq_delivery_dedupe"),
    )
    op.create_index("ix_deliveries_channel", "notification_deliveries", ["channel_id"])


def downgrade() -> None:
    op.drop_index("ix_deliveries_channel", table_name="notification_deliveries")
    op.drop_table("notification_deliveries")
    op.drop_table("notification_channels")

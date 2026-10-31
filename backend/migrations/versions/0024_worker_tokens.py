"""Scoped worker identities.

Revision ID: 0024_worker_tokens
Revises: 0023_schedules
Create Date: 2026-10-31
"""
from alembic import op
import sqlalchemy as sa

revision = "0024_worker_tokens"
down_revision = "0023_schedules"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "worker_tokens",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("worker_id", sa.String(36), sa.ForeignKey("workers.id"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("label", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_worker_tokens_hash", "worker_tokens", ["token_hash"],
                    unique=True)


def downgrade() -> None:
    op.drop_index("ix_worker_tokens_hash", table_name="worker_tokens")
    op.drop_table("worker_tokens")

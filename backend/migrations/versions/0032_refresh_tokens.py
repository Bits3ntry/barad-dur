"""Add refresh token columns to user_sessions.

Revision ID: 0032_refresh_tokens
Revises: 0031_project_groups
Create Date: 2026-11-02
"""
from alembic import op
import sqlalchemy as sa

revision = "0032_refresh_tokens"
down_revision = "0031_project_groups"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "user_sessions",
        sa.Column("refresh_token_hash", sa.String(64), nullable=True))
    op.create_index("ix_user_sessions_refresh_token_hash",
                    "user_sessions", ["refresh_token_hash"])
    op.add_column(
        "user_sessions",
        sa.Column("refresh_token_expires_at",
                  sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_index("ix_user_sessions_refresh_token_hash",
                  table_name="user_sessions")
    op.drop_column("user_sessions", "refresh_token_expires_at")
    op.drop_column("user_sessions", "refresh_token_hash")

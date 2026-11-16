"""device authorizations: the table behind `shauron login`

A terminal asks for a code, a human approves it in the console, and the terminal
trades a secret for a session. The secret is hashed; the short code is not, because
it is worthless without the secret and lives for eight minutes.

Revision ID: 0053_device_authorizations
Revises: 0052_grant_requests
Create Date: 2026-11-06
"""

from alembic import op
import sqlalchemy as sa


revision = "0053_device_authorizations"
down_revision = "0052_grant_requests"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "device_authorizations",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("user_code", sa.String(length=16), nullable=False),
        sa.Column("device_code_hash", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False,
                  server_default="pending"),
        sa.Column("hostname", sa.String(length=128), nullable=True),
        sa.Column("platform", sa.String(length=64), nullable=True),
        sa.Column("agent", sa.String(length=64), nullable=True),
        sa.Column("org_id", sa.String(length=36),
                  sa.ForeignKey("organizations.id"), nullable=True),
        sa.Column("user_id", sa.String(length=36),
                  sa.ForeignKey("users.id"), nullable=True),
        sa.Column("decided_by", sa.String(length=320), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_polled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("polls", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_device_authorizations_user_code", "device_authorizations",
                    ["user_code"], unique=True)
    op.create_index("ix_device_authorizations_device_code_hash",
                    "device_authorizations", ["device_code_hash"], unique=True)
    op.create_index("ix_device_authorizations_status", "device_authorizations",
                    ["status"])


def downgrade() -> None:
    op.drop_index("ix_device_authorizations_status", table_name="device_authorizations")
    op.drop_index("ix_device_authorizations_device_code_hash",
                  table_name="device_authorizations")
    op.drop_index("ix_device_authorizations_user_code", table_name="device_authorizations")
    op.drop_table("device_authorizations")

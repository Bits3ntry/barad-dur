"""B2: org members (identity + roles) and the per-org hash-chained audit log.

Revision ID: 0006_identity_audit
Revises: 0005_lifecycle
Create Date: 2026-10-30
"""
from alembic import op
import sqlalchemy as sa

revision = "0006_identity_audit"
down_revision = "0005_lifecycle"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "org_members",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("identity", sa.String(255), nullable=False),
        sa.Column("role", sa.String(32), nullable=False, default="viewer"),
        sa.Column("added_by", sa.String(255), nullable=True),
        sa.Column("status", sa.String(32), nullable=False, default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "identity", name="uq_org_members_identity"),
    )
    op.create_table(
        "audit_log",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False, default="system"),
        sa.Column("action", sa.String(255), nullable=False),
        sa.Column("resource_type", sa.String(64), nullable=True),
        sa.Column("resource_id", sa.String(64), nullable=True),
        sa.Column("detail", sa.Text, nullable=True),
        sa.Column("chain_position", sa.Integer, nullable=False),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_log_org_position", "audit_log", ["org_id", "chain_position"])


def downgrade() -> None:
    op.drop_table("audit_log")
    op.drop_table("org_members")

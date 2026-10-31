"""BL-015: scan authorization engine — grants, targets, occurrences groundwork.

Revision ID: 0012_authorization
Revises: 0011_priority_intel
Create Date: 2026-10-31
"""
from alembic import op
import sqlalchemy as sa

revision = "0012_authorization"
down_revision = "0011_priority_intel"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_grants",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        # principal: who/what WILL run (user, runner id, sensor token id, ci run).
        sa.Column("principal", sa.String(255), nullable=False),
        # capabilities from the catalog (comma list, keep one row readable).
        sa.Column("capabilities", sa.String(255), nullable=False),
        sa.Column("tools", sa.String(512), nullable=True),
        sa.Column("environment", sa.String(64), nullable=True),
        sa.Column("conditions", sa.Text, nullable=True),
        sa.Column("issued_by", sa.String(255), nullable=False),
        sa.Column("justification", sa.Text, nullable=False),
        sa.Column("policy_version", sa.Integer, nullable=False),
        sa.Column("status", sa.String(32), nullable=False, default="active"),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(255), nullable=True),
        sa.Column("revocation_reason", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "scan_grant_targets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("grant_id", sa.String(36), sa.ForeignKey("scan_grants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=False),
        sa.Column("target_value", sa.String(1024), nullable=False),
    )
    op.create_index("ix_scan_grant_targets_grant", "scan_grant_targets", ["grant_id"])


def downgrade() -> None:
    op.drop_index("ix_scan_grant_targets_grant", table_name="scan_grant_targets")
    op.drop_table("scan_grant_targets")
    op.drop_table("scan_grants")

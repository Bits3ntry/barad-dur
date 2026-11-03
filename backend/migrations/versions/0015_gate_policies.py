"""BL-055: deterministic quality gate policies.

Revision ID: 0015_gate_policies
Revises: 0014_licenses
Create Date: 2026-10-31
"""
from alembic import op
import sqlalchemy as sa

revision = "0015_gate_policies"
down_revision = "0014_licenses"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "gate_policies",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("scope_type", sa.String(16), nullable=False, default="org"),
        sa.Column("scope_id", sa.String(36), nullable=True),
        sa.Column("max_severity", sa.String(16), nullable=False, default="HIGH"),
        sa.Column("block_kev", sa.Boolean, nullable=False, default=False),
        sa.Column("block_license_denied", sa.Boolean, nullable=False, default=False),
        sa.Column("include_suppressed", sa.Boolean, nullable=False, default=False),
        sa.Column("status", sa.String(32), nullable=False, default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "name", name="uq_gate_policies_name"),
    )


def downgrade() -> None:
    op.drop_table("gate_policies")

"""BL-090: asset snapshots and change detection.

Revision ID: 0016_asset_snapshots
Revises: 0015_gate_policies
Create Date: 2026-10-31
"""
from alembic import op
import sqlalchemy as sa

revision = "0016_asset_snapshots"
down_revision = "0015_gate_policies"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "asset_snapshots",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id"), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(64), nullable=False, default="manual"),
        # Structured observation: ip / cname / tech[] / tls issuer+expiry /
        # status codes / headers digest. Stored as JSON text (portable).
        sa.Column("data", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_asset_snapshots_asset", "asset_snapshots", ["asset_id", "observed_at"])


def downgrade() -> None:
    op.drop_index("ix_asset_snapshots_asset", table_name="asset_snapshots")
    op.drop_table("asset_snapshots")

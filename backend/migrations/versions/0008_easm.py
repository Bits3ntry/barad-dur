"""B4: attack surface assets (EASM) — org-scoped domain/subdomain inventory.

Revision ID: 0008_easm
Revises: 0007_intel
Create Date: 2026-10-30
"""
from alembic import op
import sqlalchemy as sa

revision = "0008_easm"
down_revision = "0007_intel"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("value", sa.String(1024), nullable=False),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("detail", sa.Text, nullable=True),
        sa.UniqueConstraint("org_id", "type", "value", name="uq_assets_triple"),
    )
    op.create_index("ix_assets_type", "assets", ["type"])


def downgrade() -> None:
    op.drop_index("ix_assets_type", table_name="assets")
    op.drop_table("assets")

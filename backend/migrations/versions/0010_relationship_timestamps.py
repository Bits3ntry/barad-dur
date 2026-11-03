"""BL-010 fix-up: created_at for repositories and services.

The 0009 migration shipped these tables without timestamps while the ORM
declares created_at; a drift family we keep catching. Additive fix-up (no
rewrite of an already-applied migration).

Revision ID: 0010_relationship_timestamps
Revises: 0009_relationships
Create Date: 2026-10-31
"""
from alembic import op
import sqlalchemy as sa

revision = "0010_relationship_timestamps"
down_revision = "0009_relationships"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table in ("repositories", "services"):
        op.add_column(table, sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False,
            server_default=sa.text("now()")))


def downgrade() -> None:
    for table in ("repositories", "services"):
        op.drop_column(table, "created_at")

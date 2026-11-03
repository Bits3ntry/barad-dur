"""BL-KEV1: priority rules gain the intel criterion (match_intel='kev').

Revision ID: 0011_priority_intel
Revises: 0010_relationship_timestamps
Create Date: 2026-10-31
"""
from alembic import op
import sqlalchemy as sa

revision = "0011_priority_intel"
down_revision = "0010_relationship_timestamps"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("priority_rules", sa.Column("match_intel", sa.String(32), nullable=True))


def downgrade() -> None:
    op.drop_column("priority_rules", "match_intel")

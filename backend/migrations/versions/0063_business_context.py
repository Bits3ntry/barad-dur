"""business context: the crown jewels, and what makes them worth defending

A thousand domains is not a thousand priorities: three or four of them carry the
business, and everything downstream — threat model, cycle selection, reachability —
is anchored on those. This column is that judgement, on its own axis:

    classification_status  is it ours?            (inventory)
    criticality            does it matter, how much?  (this table)
    grants                 what may we do to it?  (authorization)

No level is derived from a score and none is filled by a default: a host nobody
has judged answers `unclassified`, which is a fact, not a middle value.

Revision ID: 0063_business_context
Revises: 0062_cycle_kind
Create Date: 2026-11-09
"""

from alembic import op
import sqlalchemy as sa


revision = "0063_business_context"
down_revision = "0062_cycle_kind"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("criticality", sa.String(length=16), nullable=True))
    op.add_column("assets", sa.Column("business_service", sa.String(length=255), nullable=True))
    op.add_column("assets", sa.Column("criticality_reason", sa.Text(), nullable=True))
    op.add_column("assets", sa.Column("criticality_set_by", sa.String(length=255), nullable=True))
    op.add_column("assets", sa.Column("criticality_updated_at",
                                      sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_assets_criticality", "assets", ["criticality"])


def downgrade() -> None:
    op.drop_index("ix_assets_criticality", table_name="assets")
    op.drop_column("assets", "criticality_updated_at")
    op.drop_column("assets", "criticality_set_by")
    op.drop_column("assets", "criticality_reason")
    op.drop_column("assets", "business_service")
    op.drop_column("assets", "criticality")

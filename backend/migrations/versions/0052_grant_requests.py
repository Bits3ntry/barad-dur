"""authorization requests: a grant is born `requested` and an admin approves it

Declaring an asset no longer stops at the inventory row: it emits the
authorization request in the same transaction, so the domain exists and the
question "may we touch it?" exists with it. Nothing here grants anything —
`authorization.authorize` only reads grants with `status="active"`.

Revision ID: 0052_grant_requests
Revises: 0051_internal_runs
Create Date: 2026-11-06
"""

from alembic import op
import sqlalchemy as sa


revision = "0052_grant_requests"
down_revision = "0051_internal_runs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scan_grants",
                  sa.Column("level", sa.String(length=16), nullable=False,
                            server_default="simple"))
    op.add_column("scan_grants",
                  sa.Column("requested_by", sa.String(length=255), nullable=True))
    op.add_column("scan_grants",
                  sa.Column("approved_by", sa.String(length=255), nullable=True))
    op.add_column("scan_grants", sa.Column("rejection_reason", sa.Text(), nullable=True))
    op.add_column("scan_grants",
                  sa.Column("asset_id", sa.String(length=36), nullable=True))
    op.add_column("scan_grants",
                  sa.Column("source", sa.String(length=24), nullable=False,
                            server_default="manual"))
    op.create_foreign_key("fk_scan_grants_asset", "scan_grants", "assets",
                          ["asset_id"], ["id"])
    op.create_index("ix_scan_grants_asset_id", "scan_grants", ["asset_id"])


def downgrade() -> None:
    op.drop_index("ix_scan_grants_asset_id", table_name="scan_grants")
    op.drop_constraint("fk_scan_grants_asset", "scan_grants", type_="foreignkey")
    op.drop_column("scan_grants", "source")
    op.drop_column("scan_grants", "asset_id")
    op.drop_column("scan_grants", "rejection_reason")
    op.drop_column("scan_grants", "approved_by")
    op.drop_column("scan_grants", "requested_by")
    op.drop_column("scan_grants", "level")

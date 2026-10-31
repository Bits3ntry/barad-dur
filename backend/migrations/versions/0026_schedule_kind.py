"""Schedules can now also drive EASM collection.

Revision ID: 0026_schedule_kind
Revises: 0025_notifications
Create Date: 2026-10-31
"""
from alembic import op
import sqlalchemy as sa

revision = "0026_schedule_kind"
down_revision = "0025_notifications"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scan_schedules",
                  sa.Column("kind", sa.String(16), nullable=False,
                            server_default="scan"))
    op.add_column("scan_schedules",
                  sa.Column("asset_id", sa.String(36), nullable=True))
    op.create_foreign_key("fk_schedules_asset", "scan_schedules", "assets",
                          ["asset_id"], ["id"])


def downgrade() -> None:
    op.drop_constraint("fk_schedules_asset", "scan_schedules", type_="foreignkey")
    op.drop_column("scan_schedules", "asset_id")
    op.drop_column("scan_schedules", "kind")

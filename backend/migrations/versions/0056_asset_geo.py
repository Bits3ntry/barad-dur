"""asset geo: where an address is, cached so the map is not a request per view

A geolocation is a fact about an address at a moment, not about a hostname: ten
subdomains on one box share it. Caching it per asset keeps the asset page honest
(it shows when the lookup happened) without asking a third party every time the
console repaints.

The lookup is opt-in (`PLATFORM_GEOIP_URL`). With no geolocator configured the
table stays empty and the page says so instead of drawing a map of nowhere.

Revision ID: 0056_asset_geo
Revises: 0055_chat_sessions
Create Date: 2026-11-07
"""

from alembic import op
import sqlalchemy as sa


revision = "0056_asset_geo"
down_revision = "0055_chat_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "asset_geo",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"),
                  nullable=False),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id"),
                  nullable=False),
        sa.Column("address", sa.String(64), nullable=False),
        sa.Column("data", sa.Text(), nullable=True),
        sa.Column("source", sa.String(64), nullable=True),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("asset_id", "address", name="uq_asset_geo_asset_address"),
    )
    op.create_index("ix_asset_geo_asset", "asset_geo", ["asset_id"])


def downgrade() -> None:
    op.drop_index("ix_asset_geo_asset", table_name="asset_geo")
    op.drop_table("asset_geo")

"""Migration 0044: deployment-wide settings managed from the console.

One small table. Email delivery is the first entry; the shape (non-secret JSON
plus a sealed secret) covers any later deployment-wide credential without a
second migration.
"""
from alembic import op
import sqlalchemy as sa

revision = "0044_platform_settings"
down_revision = "0043_onboarding"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "platform_settings",
        sa.Column("name", sa.String(64), primary_key=True),
        sa.Column("value", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("secret_cipher", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_by", sa.String(320), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("platform_settings")

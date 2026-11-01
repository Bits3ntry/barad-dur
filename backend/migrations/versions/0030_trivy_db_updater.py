"""Migration 0030: Trivy DB updater table.

Adds the TrivyDbUpdate table used by the offline updater (GAP-08) to track
fetch, verify, publish and freshness of the Trivy vulnerability database.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import schema

revision = "0030"
down_revision = "0029_sast_baselines"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "trivy_db_updates",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"),
                  nullable=False, index=True),
        sa.Column("status", sa.String(32),
                  server_default="pending", index=True),
        sa.Column("target_filename", sa.String(512), nullable=True),
        sa.Column("target_size", sa.Integer, server_default="0"),
        sa.Column("target_sha256", sa.String(64), nullable=True),
        sa.Column("header_version", sa.String(64), nullable=True),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("TIMEZONE('utc', NOW())")),
        sa.Column("last_scheduled_at", sa.DateTime(timezone=True),
                  nullable=True),
        sa.Column("last_successful_at", sa.DateTime(timezone=True),
                  nullable=True),
        sa.UniqueConstraint("org_id", "status",
                            name="uq_trivy_db_status"),
    )


def downgrade():
    op.drop_table("trivy_db_updates")

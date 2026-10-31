"""SBOM baselines: a frozen component set to compare future versions against.

Revision ID: 0027_sbom_baselines
Revises: 0026_schedule_kind
Create Date: 2026-10-31
"""
from alembic import op
import sqlalchemy as sa

revision = "0027_sbom_baselines"
down_revision = "0026_schedule_kind"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sbom_baselines",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("project_version_id", sa.String(36),
                  sa.ForeignKey("project_versions.id"), nullable=False),
        sa.Column("components", sa.Text, nullable=False),
        sa.Column("component_count", sa.Integer, nullable=False, default=0),
        sa.Column("note", sa.Text, nullable=True),
        sa.Column("created_by", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("project_version_id", name="uq_baseline_version"),
    )


def downgrade() -> None:
    op.drop_table("sbom_baselines")

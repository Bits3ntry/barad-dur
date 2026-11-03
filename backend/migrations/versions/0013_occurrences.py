"""BL-040: occurrence rows — every sighting of one finding, deduped upstream.

Revision ID: 0013_occurrences
Revises: 0012_authorization
Create Date: 2026-10-31
"""
from alembic import op
import sqlalchemy as sa

revision = "0013_occurrences"
down_revision = "0012_authorization"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "occurrences",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id"), nullable=False),
        # Context of the sighting (never a join against versions).
        sa.Column("project_version_id", sa.String(36),
                  sa.ForeignKey("project_versions.id"), nullable=True),
        sa.Column("ci_run_id", sa.String(36),
                  sa.ForeignKey("ci_runs.id"), nullable=True),
        sa.Column("tool", sa.String(64), nullable=True),
        sa.Column("source", sa.String(32), nullable=True),
        sa.Column("sighting_key", sa.String(64), nullable=False),
        sa.Column("evidence", sa.Text, nullable=True),
        sa.Column("seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("finding_id", "sighting_key",
                            name="uq_occurrence_sighting"),
    )
    op.create_index("ix_occurrences_finding", "occurrences", ["finding_id"])


def downgrade() -> None:
    op.drop_index("ix_occurrences_finding", table_name="occurrences")
    op.drop_table("occurrences")

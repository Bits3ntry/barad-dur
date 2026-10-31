"""Migration 0028: named SAST baselines with an approval gate."""
from alembic import op
import sqlalchemy as sa


revision = "0028_sast_baselines"
down_revision = "0027_sbom_baselines"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sast_baselines",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"),
                  nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("repository_id", sa.String(36),
                  sa.ForeignKey("repositories.id"), nullable=True),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id"),
                  nullable=True),
        sa.Column("status", sa.String(16), nullable=False, default="draft"),
        sa.Column("entries", sa.JSON(), nullable=False),
        sa.Column("counters", sa.JSON(), nullable=False),
        sa.Column("source_pr_id", sa.String(36), nullable=True),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("approved_by", sa.String(255), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "name", name="uq_sast_baseline_name"),
    )
    op.create_index("ix_sast_baselines_org", "sast_baselines", ["org_id"])
    op.create_index("ix_sast_baselines_repo", "sast_baselines",
                    ["repository_id", "status"])


def downgrade() -> None:
    op.drop_index("ix_sast_baselines_repo", table_name="sast_baselines")
    op.drop_index("ix_sast_baselines_org", table_name="sast_baselines")
    op.drop_table("sast_baselines")

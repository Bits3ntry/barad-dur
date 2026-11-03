"""Migration 0041: an analysis run knows which repository (and PR) it came from.

The project/version pair says what the code belongs to; this says exactly which
remote and pull request were analysed, which is what a reviewer needs to open
the same code at the same place.
"""
from alembic import op
import sqlalchemy as sa

revision = "0041_analysis_origin"
down_revision = "0040_sbom_artifact"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("analysis_runs") as batch:
        batch.add_column(sa.Column("repository_id", sa.String(36),
                                   sa.ForeignKey("repositories.id"), nullable=True))
        batch.add_column(sa.Column("pull_request", sa.String(64), nullable=True))
    op.create_index("ix_analysis_runs_repository", "analysis_runs", ["repository_id"])


def downgrade() -> None:
    op.drop_index("ix_analysis_runs_repository", table_name="analysis_runs")
    with op.batch_alter_table("analysis_runs") as batch:
        batch.drop_column("pull_request")
        batch.drop_column("repository_id")

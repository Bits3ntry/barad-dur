"""Migration 0040: an SBOM receipt can name the artifact it describes.

The document still belongs to a project version; the artifact link is what makes
"which build is this SBOM for" answerable, and a deployment can then point at
that artifact.
"""
from alembic import op
import sqlalchemy as sa

revision = "0040_sbom_artifact"
down_revision = "0039_cycles_and_work"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("sbom_imports") as batch:
        batch.add_column(sa.Column("artifact_id", sa.String(36),
                                   sa.ForeignKey("artifacts.id"), nullable=True))
    op.create_index("ix_sbom_imports_artifact", "sbom_imports", ["artifact_id"])


def downgrade() -> None:
    op.drop_index("ix_sbom_imports_artifact", table_name="sbom_imports")
    with op.batch_alter_table("sbom_imports") as batch:
        batch.drop_column("artifact_id")

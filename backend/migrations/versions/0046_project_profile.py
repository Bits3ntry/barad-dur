"""Migration 0046: a project carries its own context.

`description` (what the product does) and `owner` (who answers for it) are what
the inventory screen asks for while creating a project. Both nullable, free
text — a project is an organizational unit, not a schema.
"""
from alembic import op
import sqlalchemy as sa

revision = "0046_project_profile"
down_revision = "0045_inventory_projects"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("projects") as batch:
        batch.add_column(sa.Column("description", sa.Text(), nullable=True))
        batch.add_column(sa.Column("owner", sa.String(255), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("projects") as batch:
        batch.drop_column("owner")
        batch.drop_column("description")

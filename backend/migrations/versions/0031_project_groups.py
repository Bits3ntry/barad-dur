"""Migration 0031: project groups.

A repository is rarely the unit someone reports on: Aurea is four repositories
and reading them one by one is what made the portfolio unreadable. `group_name`
is the product/account above the project — free text, nullable, so nothing has
to be decided at write time.
"""

from alembic import op
import sqlalchemy as sa

revision = "0031_project_groups"
down_revision = "0030_trivy_db_updater"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("projects", sa.Column("group_name", sa.String(128), nullable=True))
    op.create_index("ix_projects_group_name", "projects", ["group_name"])


def downgrade():
    op.drop_index("ix_projects_group_name", table_name="projects")
    op.drop_column("projects", "group_name")

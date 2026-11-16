"""crown jewels are projects, not domains

A jewel is the thing whose compromise hurts the business: the backend, the checkout,
the customer app. Its domains, versions and environments are consequences of that
judgement, not the judgement itself — and a thousand registered domains are not a
thousand priorities.

So the business level moves from `assets` to `projects`, and the asset columns added
in 0063 are dropped in the same revision: two places to record "this matters" is
exactly the drift this revision exists to prevent. No data is migrated because the
asset-level level was never used to make a decision (0063 shipped hours earlier and
its only row was withdrawn by its author).

Revision ID: 0064_project_crown_jewels
Revises: 0063_business_context
Create Date: 2026-11-09
"""

from alembic import op
import sqlalchemy as sa


revision = "0064_project_crown_jewels"
down_revision = "0063_business_context"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("projects", sa.Column("criticality", sa.String(length=16), nullable=True))
    op.add_column("projects", sa.Column("business_service", sa.String(length=255), nullable=True))
    op.add_column("projects", sa.Column("criticality_reason", sa.Text(), nullable=True))
    op.add_column("projects", sa.Column("criticality_set_by", sa.String(length=255), nullable=True))
    op.add_column("projects", sa.Column("criticality_updated_at",
                                        sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_projects_criticality", "projects", ["criticality"])

    # The judgement lives in one place from now on.
    op.drop_index("ix_assets_criticality", table_name="assets")
    op.drop_column("assets", "criticality_updated_at")
    op.drop_column("assets", "criticality_set_by")
    op.drop_column("assets", "criticality_reason")
    op.drop_column("assets", "business_service")
    op.drop_column("assets", "criticality")


def downgrade() -> None:
    op.add_column("assets", sa.Column("criticality", sa.String(length=16), nullable=True))
    op.add_column("assets", sa.Column("business_service", sa.String(length=255), nullable=True))
    op.add_column("assets", sa.Column("criticality_reason", sa.Text(), nullable=True))
    op.add_column("assets", sa.Column("criticality_set_by", sa.String(length=255), nullable=True))
    op.add_column("assets", sa.Column("criticality_updated_at",
                                      sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_assets_criticality", "assets", ["criticality"])

    op.drop_index("ix_projects_criticality", table_name="projects")
    op.drop_column("projects", "criticality_updated_at")
    op.drop_column("projects", "criticality_set_by")
    op.drop_column("projects", "criticality_reason")
    op.drop_column("projects", "business_service")
    op.drop_column("projects", "criticality")

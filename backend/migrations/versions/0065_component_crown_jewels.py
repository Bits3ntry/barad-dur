"""the crown jewel is a component: AUREA > Backend, not AUREA

A project is a product container (it holds the backend, the web, the fx service).
What the business runs — and what a compromise actually takes down — is one of those
services. So the business level moves from `projects` to `application_components`.

No data is migrated: the project-level level existed for one revision and its only
row was the baseline designation its author set while testing, which is re-made at
the component level.

Revision ID: 0065_component_crown_jewels
Revises: 0064_project_crown_jewels
Create Date: 2026-11-09
"""

from alembic import op
import sqlalchemy as sa


revision = "0065_component_crown_jewels"
down_revision = "0064_project_crown_jewels"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("application_components", sa.Column(
        "criticality", sa.String(length=16), nullable=True))
    op.add_column("application_components", sa.Column(
        "business_service", sa.String(length=255), nullable=True))
    op.add_column("application_components", sa.Column(
        "criticality_reason", sa.Text(), nullable=True))
    op.add_column("application_components", sa.Column(
        "criticality_set_by", sa.String(length=255), nullable=True))
    op.add_column("application_components", sa.Column(
        "criticality_updated_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_app_components_criticality", "application_components",
                    ["criticality"])

    op.drop_index("ix_projects_criticality", table_name="projects")
    op.drop_column("projects", "criticality_updated_at")
    op.drop_column("projects", "criticality_set_by")
    op.drop_column("projects", "criticality_reason")
    op.drop_column("projects", "business_service")
    op.drop_column("projects", "criticality")


def downgrade() -> None:
    op.add_column("projects", sa.Column("criticality", sa.String(length=16), nullable=True))
    op.add_column("projects", sa.Column("business_service", sa.String(length=255), nullable=True))
    op.add_column("projects", sa.Column("criticality_reason", sa.Text(), nullable=True))
    op.add_column("projects", sa.Column("criticality_set_by", sa.String(length=255), nullable=True))
    op.add_column("projects", sa.Column("criticality_updated_at",
                                        sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_projects_criticality", "projects", ["criticality"])

    op.drop_index("ix_app_components_criticality", table_name="application_components")
    op.drop_column("application_components", "criticality_updated_at")
    op.drop_column("application_components", "criticality_set_by")
    op.drop_column("application_components", "criticality_reason")
    op.drop_column("application_components", "business_service")
    op.drop_column("application_components", "criticality")

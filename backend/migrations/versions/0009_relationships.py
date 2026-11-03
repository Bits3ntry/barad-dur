"""BL-010: typed, temporal, auditable relationships.

repositories, services, deployments as independent entities; project↔repo and
service↔project links; polymorphic typed links for assets (asset_links) and
finding context (finding_contexts) — discovered assets may exist without any
project or repository, and one asset/project may appear on both sides of a
many-to-many without any row duplication (links are separate rows; both
point at the same entities).

Revision ID: 0009_relationships
Revises: 0008_easm
Create Date: 2026-10-31
"""
from alembic import op
import sqlalchemy as sa

revision = "0009_relationships"
down_revision = "0008_easm"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "repositories",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False, default="git"),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("remote_url", sa.String(2048), nullable=False),
        sa.Column("last_commit_sha", sa.String(64), nullable=True),
        sa.UniqueConstraint("org_id", "remote_url", name="uq_repositories_remote"),
    )
    op.create_table(
        "project_repositories",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("repository_id", sa.String(36), sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("relation", sa.String(32), nullable=False, default="builds"),
        sa.Column("added_by", sa.String(255), nullable=True),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_project_repositories_project", "project_repositories", ["project_id"])

    op.create_table(
        "services",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("runtime", sa.String(64), nullable=True),
        sa.Column("owner", sa.String(255), nullable=True),
        sa.UniqueConstraint("org_id", "name", name="uq_services_org_name"),
    )
    op.create_table(
        "service_projects",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("service_id", sa.String(36), sa.ForeignKey("services.id"), nullable=False),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("relation", sa.String(32), nullable=False, default="exposes"),
        sa.Column("added_by", sa.String(255), nullable=True),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "deployments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("service_id", sa.String(36), sa.ForeignKey("services.id"), nullable=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("environment", sa.String(64), nullable=False, default="production"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    # Polymorphic typed links: one row per (asset, entity, relation) pairing.
    # Assets stay first-class without any project or service; linking is
    # additive and temporal, so shared assets never duplicate.
    op.create_table(
        "asset_links",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id"), nullable=False),
        sa.Column("entity_type", sa.String(32), nullable=False),
        sa.Column("entity_id", sa.String(36), nullable=False),
        sa.Column("relation", sa.String(32), nullable=False, default="serves"),
        sa.Column("added_by", sa.String(255), nullable=True),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_asset_links_asset", "asset_links", ["asset_id"])
    op.create_index("ix_asset_links_entity", "asset_links", ["entity_type", "entity_id"])
    # Findings gain contextual links beyond project/version/component.
    op.create_table(
        "finding_contexts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("entity_type", sa.String(32), nullable=False),
        sa.Column("entity_id", sa.String(36), nullable=False),
        sa.Column("relation", sa.String(32), nullable=False, default="observed_in"),
        sa.Column("added_by", sa.String(255), nullable=True),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_finding_contexts_finding", "finding_contexts", ["finding_id"])


def downgrade() -> None:
    op.drop_table("finding_contexts")
    op.drop_table("asset_links")
    op.drop_table("deployments")
    op.drop_table("service_projects")
    op.drop_table("services")
    op.drop_index("ix_project_repositories_project", table_name="project_repositories")
    op.drop_table("project_repositories")
    op.drop_table("repositories")

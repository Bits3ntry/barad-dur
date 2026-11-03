"""F0 core schema: organizations, keys, projects, versions, SBOM imports, components.

Revision ID: 0001_core
Revises:
Create Date: 2026-10-30
"""
from alembic import op
import sqlalchemy as sa

revision = "0001_core"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("slug", sa.String(64), nullable=False, unique=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "api_keys",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("label", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_api_keys_key_hash", "api_keys", ["key_hash"])
    op.create_table(
        "projects",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "slug", name="uq_projects_org_slug"),
    )
    op.create_table(
        "project_versions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("version", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("project_id", "version", name="uq_project_versions_pair"),
    )
    op.create_table(
        "sbom_imports",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("project_version_id", sa.String(36),
                  sa.ForeignKey("project_versions.id"), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("filename", sa.String(512), nullable=True),
        sa.Column("components_received", sa.Integer, nullable=False),
        sa.Column("components_created", sa.Integer, nullable=False),
        sa.Column("components_updated", sa.Integer, nullable=False),
        sa.Column("components_skipped", sa.Integer, nullable=False),
        sa.Column("links_created", sa.Integer, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("project_version_id", "content_sha256",
                            name="uq_sbom_import_idempotent"),
    )
    op.create_table(
        "components",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("identity_key", sa.String(1100), nullable=False),
        sa.Column("purl", sa.String(1024), nullable=True),
        sa.Column("bom_ref", sa.String(1024), nullable=True),
        sa.Column("name", sa.String(512), nullable=True),
        sa.Column("version", sa.String(255), nullable=True),
        sa.Column("license", sa.String(512), nullable=True),
        sa.Column("manifest_path", sa.String(1024), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "identity_key", name="uq_components_org_identity"),
    )
    op.create_index("ix_components_identity_key", "components", ["identity_key"])
    op.create_table(
        "version_components",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("project_version_id", sa.String(36),
                  sa.ForeignKey("project_versions.id"), nullable=False),
        sa.Column("component_id", sa.String(36), sa.ForeignKey("components.id"), nullable=False),
        sa.Column("is_direct", sa.Boolean, nullable=False),
        sa.Column("parent_purl", sa.String(1024), nullable=True),
        sa.Column("manifest_path", sa.String(1024), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("project_version_id", "component_id",
                            name="uq_version_components_pair"),
    )


def downgrade() -> None:
    op.drop_table("version_components")
    op.drop_table("components")
    op.drop_table("sbom_imports")
    op.drop_table("project_versions")
    op.drop_table("projects")
    op.drop_table("api_keys")
    op.drop_table("organizations")

"""Migration 0033: v0 inventory — application components, artifacts, groups,
asset ownership, finding owner/narrative/evidence.

Additive only. Deployments gain the pointer to what is actually running
(artifact), assets gain the ownership/classification columns the inventory
screen owes a reader, and findings gain owner + narrative + comments and
attachments. Inventory groups are N:M over assets and are unrelated to access
control: membership here never grants a permission.
"""
from alembic import op
import sqlalchemy as sa

revision = "0033_v0_inventory"
down_revision = "0032_refresh_tokens"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "application_components",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("kind", sa.String(24), nullable=False, server_default="backend"),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("project_id", "slug", name="uq_app_component_slug"),
    )
    op.create_index("ix_application_components_org", "application_components", ["org_id"])
    op.create_index("ix_application_components_project", "application_components",
                    ["project_id"])

    op.create_table(
        "artifacts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("project_version_id", sa.String(36),
                  sa.ForeignKey("project_versions.id"), nullable=True),
        sa.Column("application_component_id", sa.String(36),
                  sa.ForeignKey("application_components.id"), nullable=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("digest", sa.String(128), nullable=True),
        sa.Column("digest_algorithm", sa.String(32), nullable=True),
        sa.Column("provenance", sa.String(255), nullable=True),
        sa.Column("source", sa.String(32), nullable=False, server_default="import"),
        sa.Column("build_ref", sa.String(255), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "digest", name="uq_artifact_digest"),
    )
    op.create_index("ix_artifacts_org", "artifacts", ["org_id"])
    op.create_index("ix_artifacts_version", "artifacts", ["project_version_id"])

    op.create_table(
        "inventory_groups",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "name", name="uq_inventory_group_name"),
    )
    op.create_index("ix_inventory_groups_org", "inventory_groups", ["org_id"])

    op.create_table(
        "inventory_group_members",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("group_id", sa.String(36),
                  sa.ForeignKey("inventory_groups.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id"), nullable=False),
        sa.Column("added_by", sa.String(255), nullable=True),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("group_id", "asset_id", name="uq_group_asset"),
    )
    op.create_index("ix_group_members_org", "inventory_group_members", ["org_id"])
    op.create_index("ix_group_members_group", "inventory_group_members", ["group_id"])
    op.create_index("ix_group_members_asset", "inventory_group_members", ["asset_id"])

    op.create_table(
        "inventory_group_stakeholders",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("group_id", sa.String(36),
                  sa.ForeignKey("inventory_groups.id", ondelete="CASCADE"), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("role", sa.String(24), nullable=False, server_default="collaborator"),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("group_id", "actor", name="uq_group_stakeholder"),
    )
    op.create_index("ix_group_stakeholders_group", "inventory_group_stakeholders",
                    ["group_id"])

    op.create_table(
        "finding_comments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("finding_id", sa.String(36),
                  sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("author", sa.String(255), nullable=True),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_finding_comments_org", "finding_comments", ["org_id"])
    op.create_index("ix_finding_comments_finding", "finding_comments", ["finding_id"])

    op.create_table(
        "finding_attachments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("finding_id", sa.String(36),
                  sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("media_type", sa.String(128), nullable=False, server_default="text/plain"),
        sa.Column("size_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("redaction_state", sa.String(24), nullable=False,
                  server_default="unreviewed"),
        sa.Column("added_by", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_finding_attachments_finding", "finding_attachments", ["finding_id"])

    with op.batch_alter_table("assets") as batch:
        batch.add_column(sa.Column("project_id", sa.String(36),
                                   sa.ForeignKey("projects.id"), nullable=True))
        batch.add_column(sa.Column("owner", sa.String(255), nullable=True))
        batch.add_column(sa.Column("classification_status", sa.String(24),
                                   nullable=False, server_default="unclassified"))
        batch.add_column(sa.Column("notes", sa.Text(), nullable=True))
        batch.add_column(sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_assets_project_id", "assets", ["project_id"])
    op.create_index("ix_assets_owner", "assets", ["owner"])
    op.create_index("ix_assets_classification", "assets", ["classification_status"])

    with op.batch_alter_table("deployments") as batch:
        batch.add_column(sa.Column("artifact_id", sa.String(36),
                                   sa.ForeignKey("artifacts.id"), nullable=True))
        batch.add_column(sa.Column("application_component_id", sa.String(36),
                                   sa.ForeignKey("application_components.id"), nullable=True))
        batch.add_column(sa.Column("status", sa.String(24), nullable=False,
                                   server_default="active"))
        batch.add_column(sa.Column("deployed_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_deployments_artifact", "deployments", ["artifact_id"])
    op.create_index("ix_deployments_status", "deployments", ["status"])

    op.add_column("findings", sa.Column("assignee", sa.String(255), nullable=True))
    op.add_column("findings", sa.Column("cwe", sa.String(64), nullable=True))
    op.add_column("findings", sa.Column("impact", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("recommendation", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("reproduction", sa.Text(), nullable=True))
    op.create_index("ix_findings_assignee", "findings", ["assignee"])


def downgrade() -> None:
    op.drop_index("ix_findings_assignee", table_name="findings")
    op.drop_column("findings", "reproduction")
    op.drop_column("findings", "recommendation")
    op.drop_column("findings", "impact")
    op.drop_column("findings", "cwe")
    op.drop_column("findings", "assignee")

    op.drop_index("ix_deployments_status", table_name="deployments")
    op.drop_index("ix_deployments_artifact", table_name="deployments")
    with op.batch_alter_table("deployments") as batch:
        batch.drop_column("retired_at")
        batch.drop_column("deployed_at")
        batch.drop_column("status")
        batch.drop_column("application_component_id")
        batch.drop_column("artifact_id")

    op.drop_index("ix_assets_classification", table_name="assets")
    op.drop_index("ix_assets_owner", table_name="assets")
    op.drop_index("ix_assets_project_id", table_name="assets")
    with op.batch_alter_table("assets") as batch:
        batch.drop_column("archived_at")
        batch.drop_column("notes")
        batch.drop_column("classification_status")
        batch.drop_column("owner")
        batch.drop_column("project_id")

    op.drop_index("ix_finding_attachments_finding", table_name="finding_attachments")
    op.drop_table("finding_attachments")
    op.drop_index("ix_finding_comments_finding", table_name="finding_comments")
    op.drop_index("ix_finding_comments_org", table_name="finding_comments")
    op.drop_table("finding_comments")
    op.drop_index("ix_group_stakeholders_group", table_name="inventory_group_stakeholders")
    op.drop_table("inventory_group_stakeholders")
    op.drop_index("ix_group_members_asset", table_name="inventory_group_members")
    op.drop_index("ix_group_members_group", table_name="inventory_group_members")
    op.drop_index("ix_group_members_org", table_name="inventory_group_members")
    op.drop_table("inventory_group_members")
    op.drop_index("ix_inventory_groups_org", table_name="inventory_groups")
    op.drop_table("inventory_groups")
    op.drop_index("ix_artifacts_version", table_name="artifacts")
    op.drop_index("ix_artifacts_org", table_name="artifacts")
    op.drop_table("artifacts")
    op.drop_index("ix_application_components_project", table_name="application_components")
    op.drop_index("ix_application_components_org", table_name="application_components")
    op.drop_table("application_components")

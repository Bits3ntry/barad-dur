"""Migration 0045: declarative inventory — component code, versions, probes.

Additive. `deployments` gains what the inventory form needs to name what is
running before any scan exists; `component_repositories` links code to a
component (a repo can back several, a component can use several); `health_probes`
holds the optional read-only version check.

`version_label` is deliberately free text: the whole point is to record
"PRO · Backend · 1.7.4" from what the team knows, and let a probe or an import
confirm it later.
"""
from alembic import op
import sqlalchemy as sa

revision = "0045_inventory_projects"
down_revision = "0044_platform_settings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("deployments") as batch:
        batch.add_column(sa.Column("version_label", sa.String(255), nullable=True))
        batch.add_column(sa.Column("exposure", sa.String(16), nullable=False,
                                   server_default="unknown"))
        batch.add_column(sa.Column("requires_auth", sa.Boolean(), nullable=False,
                                   server_default=sa.false()))
        batch.add_column(sa.Column("source", sa.String(24), nullable=False,
                                   server_default="manual"))
        batch.add_column(sa.Column("last_checked_at",
                                   sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("last_check_status", sa.String(24), nullable=True))
        batch.add_column(sa.Column("last_check_error", sa.Text(), nullable=True))

    op.create_table(
        "component_repositories",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"),
                  nullable=False),
        sa.Column("component_id", sa.String(36),
                  sa.ForeignKey("application_components.id"), nullable=False),
        sa.Column("repository_id", sa.String(36),
                  sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("relation", sa.String(32), nullable=False, server_default="code"),
        sa.Column("added_by", sa.String(320), nullable=True),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("component_id", "repository_id",
                            name="uq_component_repository"),
    )
    op.create_index("ix_component_repositories_component", "component_repositories",
                    ["component_id"])
    op.create_index("ix_component_repositories_repository", "component_repositories",
                    ["repository_id"])

    op.create_table(
        "health_probes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"),
                  nullable=False),
        sa.Column("deployment_id", sa.String(36), sa.ForeignKey("deployments.id"),
                  nullable=False),
        sa.Column("url", sa.String(1024), nullable=False),
        sa.Column("token_cipher", sa.Text(), nullable=True),
        sa.Column("version_path", sa.String(128), nullable=False, server_default="auto"),
        sa.Column("status_path", sa.String(128), nullable=False, server_default="status"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("interval_minutes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_ok_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("last_payload", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(320), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("deployment_id", name="uq_health_probe_deployment"),
    )
    op.create_index("ix_health_probes_deployment", "health_probes", ["deployment_id"])


def downgrade() -> None:
    op.drop_index("ix_health_probes_deployment", table_name="health_probes")
    op.drop_table("health_probes")
    op.drop_index("ix_component_repositories_repository",
                  table_name="component_repositories")
    op.drop_index("ix_component_repositories_component",
                  table_name="component_repositories")
    op.drop_table("component_repositories")
    with op.batch_alter_table("deployments") as batch:
        batch.drop_column("last_check_error")
        batch.drop_column("last_check_status")
        batch.drop_column("last_checked_at")
        batch.drop_column("source")
        batch.drop_column("requires_auth")
        batch.drop_column("exposure")
        batch.drop_column("version_label")

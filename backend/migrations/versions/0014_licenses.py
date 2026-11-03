"""BL-060: license inventory, policies and exceptions.

Components keep their single `license` summary column (compat), while the
full license set flows into `component_licenses` rows; policies evaluate
inventory explainably and exceptions are explicit, expiring, audited.

Revision ID: 0014_licenses
Revises: 0013_occurrences
Create Date: 2026-10-31
"""
from alembic import op
import sqlalchemy as sa

revision = "0014_licenses"
down_revision = "0013_occurrences"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "component_licenses",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("component_id", sa.String(36), sa.ForeignKey("components.id"), nullable=False),
        sa.Column("license_id", sa.String(255), nullable=False),
        sa.Column("source", sa.String(32), nullable=False, default="sbom"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("component_id", "license_id", name="uq_component_license"),
    )
    op.create_index("ix_component_licenses_license", "component_licenses", ["license_id"])
    op.create_table(
        "license_policies",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("scope_type", sa.String(16), nullable=False, default="org"),
        sa.Column("scope_id", sa.String(36), nullable=True),
        sa.Column("allow_list", sa.Text, nullable=True),
        sa.Column("deny_list", sa.Text, nullable=True),
        sa.Column("unknown_action", sa.String(16), nullable=False, default="warn"),
        sa.Column("status", sa.String(32), nullable=False, default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "name", name="uq_license_policies_name"),
    )
    op.create_table(
        "license_exceptions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("component_identity", sa.String(1100), nullable=False),
        sa.Column("license_id", sa.String(255), nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("approved_by", sa.String(255), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("license_exceptions")
    op.drop_table("license_policies")
    op.drop_index("ix_component_licenses_license", table_name="component_licenses")
    op.drop_table("component_licenses")

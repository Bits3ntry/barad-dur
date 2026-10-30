"""B1: findings lifecycle — priority (rules), SLA policies and remediation.

Revision ID: 0005_lifecycle
Revises: 0004_ci_scope
Create Date: 2026-10-30
"""
from alembic import op
import sqlalchemy as sa

revision = "0005_lifecycle"
down_revision = "0004_ci_scope"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("priority", sa.String(8), nullable=True))
    op.add_column("findings", sa.Column("priority_reason", sa.Text, nullable=True))
    op.add_column("findings", sa.Column("sla_deadline", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_findings_priority", "findings", ["priority"])
    op.create_table(
        "priority_rules",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("position", sa.Integer, nullable=False, default=0),
        sa.Column("match_kind", sa.String(32), nullable=True),
        sa.Column("match_severities", sa.String(255), nullable=True),
        sa.Column("match_source", sa.String(32), nullable=True),
        sa.Column("priority", sa.String(8), nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "sla_policies",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("p0_days", sa.Integer, nullable=False),
        sa.Column("p1_days", sa.Integer, nullable=False),
        sa.Column("p2_days", sa.Integer, nullable=False),
        sa.Column("p3_days", sa.Integer, nullable=False),
        sa.Column("is_default", sa.Boolean, nullable=False, default=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "remediation_tasks",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, default="open"),
        sa.Column("owner", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "remediation_findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("task_id", sa.String(36), sa.ForeignKey("remediation_tasks.id"), nullable=False),
        sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        # Their contract: a finding belongs to at most one open remediation task.
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("remediation_findings")
    op.drop_table("remediation_tasks")
    op.drop_table("sla_policies")
    op.drop_table("priority_rules")
    op.drop_index("ix_findings_priority", table_name="findings")
    op.drop_column("findings", "sla_deadline")
    op.drop_column("findings", "priority_reason")
    op.drop_column("findings", "priority")

"""F2: multi-kind finding context columns and the two-layer suppression model.

Revision ID: 0003_suppressions
Revises: 0002_findings
Create Date: 2026-10-30
"""
from alembic import op
import sqlalchemy as sa

revision = "0003_suppressions"
down_revision = "0002_findings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("tool", sa.String(32), nullable=True))
    op.add_column("findings", sa.Column("rule_id", sa.String(512), nullable=True))
    op.add_column("findings", sa.Column("path", sa.String(1024), nullable=True))
    op.add_column("findings", sa.Column("line", sa.Integer, nullable=True))
    op.add_column("findings", sa.Column("status_reason", sa.Text, nullable=True))
    op.add_column("findings", sa.Column("status_changed_at", sa.DateTime(timezone=True), nullable=True))
    # Multi-kind findings (secret, misconfiguration, code-weakness) carry no
    # component row, so the scan context they were last seen in is stamped
    # directly; vulnerability findings keep it too (their component link
    # remains for inventory joins).
    op.add_column("findings", sa.Column("last_seen_version_id", sa.String(36),
                  sa.ForeignKey("project_versions.id"), nullable=True))
    op.create_index("ix_findings_last_seen_version", "findings", ["last_seen_version_id"])
    op.create_index("ix_findings_project_kind", "findings", ["project_id", "kind"])
    op.create_table(
        "suppression_rules",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id"), nullable=True),
        sa.Column("kind", sa.String(32), nullable=True),
        sa.Column("rule_id", sa.String(512), nullable=True),
        sa.Column("path_pattern", sa.String(1024), nullable=True),
        sa.Column("suppression_type", sa.String(32), nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("status", sa.String(32), nullable=False, default="pending"),
        sa.Column("requested_by", sa.String(255), nullable=False),
        sa.Column("approved_by", sa.String(255), nullable=True),
        sa.Column("rejection_reason", sa.Text, nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_suppression_rules_status", "suppression_rules", ["status"])
    op.create_table(
        "finding_suppressions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("rule_id", sa.String(36), sa.ForeignKey("suppression_rules.id"), nullable=False),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("applied_by", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("finding_id", "rule_id", name="uq_finding_suppression_pair"),
    )


def downgrade() -> None:
    op.drop_table("finding_suppressions")
    op.drop_table("suppression_rules")
    op.drop_index("ix_findings_last_seen_version", table_name="findings")
    op.drop_index("ix_findings_project_kind", table_name="findings")
    op.drop_column("findings", "last_seen_version_id")
    op.drop_column("findings", "status_changed_at")
    op.drop_column("findings", "status_reason")
    op.drop_column("findings", "line")
    op.drop_column("findings", "path")
    op.drop_column("findings", "rule_id")
    op.drop_column("findings", "tool")

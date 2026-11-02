"""Migration 0039: cycles, their frozen membership, linked findings and work items.

A cycle is planning → active → review → closed. Activation freezes the charter
and the resolved membership into `cycle_memberships`, so a later group edit
never rewrites the historical reference. Work items are the tasks, decision
requests and acceptances the My work queues read.
"""
from alembic import op
import sqlalchemy as sa

revision = "0039_cycles_and_work"
down_revision = "0038_web_and_lookalikes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cycles",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("owner", sa.String(255), nullable=True),
        sa.Column("state", sa.String(16), nullable=False, server_default="planning"),
        sa.Column("starts_on", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ends_on", sa.DateTime(timezone=True), nullable=True),
        sa.Column("charter", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("selection", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("snapshot", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("snapshot_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("review", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "name", name="uq_cycle_name"),
    )
    op.create_index("ix_cycles_org", "cycles", ["org_id"])
    op.create_index("ix_cycles_state", "cycles", ["state"])

    op.create_table(
        "cycle_memberships",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("cycle_id", sa.String(36),
                  sa.ForeignKey("cycles.id", ondelete="CASCADE"), nullable=False),
        sa.Column("entity_type", sa.String(24), nullable=False),
        sa.Column("entity_id", sa.String(36), nullable=False),
        sa.Column("label", sa.String(512), nullable=True),
        sa.Column("included_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("cycle_id", "entity_type", "entity_id",
                            name="uq_cycle_membership"),
    )
    op.create_index("ix_cycle_memberships_cycle", "cycle_memberships", ["cycle_id"])
    op.create_index("ix_cycle_memberships_entity", "cycle_memberships", ["entity_id"])

    op.create_table(
        "cycle_findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("cycle_id", sa.String(36),
                  sa.ForeignKey("cycles.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id"),
                  nullable=False),
        sa.Column("linked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(16), nullable=False, server_default="manual"),
        sa.UniqueConstraint("cycle_id", "finding_id", name="uq_cycle_finding"),
    )
    op.create_index("ix_cycle_findings_cycle", "cycle_findings", ["cycle_id"])

    op.create_table(
        "work_items",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False, server_default="task"),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(24), nullable=False, server_default="open"),
        sa.Column("assignee", sa.String(255), nullable=True),
        sa.Column("requested_by", sa.String(255), nullable=True),
        sa.Column("reviewer", sa.String(255), nullable=True),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_reason", sa.Text(), nullable=True),
        sa.Column("decided_by", sa.String(255), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("remind_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_reminded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cycle_id", sa.String(36), sa.ForeignKey("cycles.id"), nullable=True),
        sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_work_items_org", "work_items", ["org_id"])
    op.create_index("ix_work_items_assignee", "work_items", ["assignee"])
    op.create_index("ix_work_items_reviewer", "work_items", ["reviewer"])
    op.create_index("ix_work_items_requested", "work_items", ["requested_by"])
    op.create_index("ix_work_items_status", "work_items", ["status"])


def downgrade() -> None:
    op.drop_index("ix_work_items_status", table_name="work_items")
    op.drop_index("ix_work_items_requested", table_name="work_items")
    op.drop_index("ix_work_items_reviewer", table_name="work_items")
    op.drop_index("ix_work_items_assignee", table_name="work_items")
    op.drop_index("ix_work_items_org", table_name="work_items")
    op.drop_table("work_items")
    op.drop_index("ix_cycle_findings_cycle", table_name="cycle_findings")
    op.drop_table("cycle_findings")
    op.drop_index("ix_cycle_memberships_entity", table_name="cycle_memberships")
    op.drop_index("ix_cycle_memberships_cycle", table_name="cycle_memberships")
    op.drop_table("cycle_memberships")
    op.drop_index("ix_cycles_state", table_name="cycles")
    op.drop_index("ix_cycles_org", table_name="cycles")
    op.drop_table("cycles")

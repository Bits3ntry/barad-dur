"""field runtime: missions, tasks and the event log (F4, D25–D28, D33–D35)

The platform's half of the acting loop. A mission is the authorization, a task is one
contract, and the events are what the field agent did while it did it — the container's
log is not the record (D61), so every relevant line is an event before the process can
exit.

Revision ID: 0058_agent_runtime
Revises: 0057_finding_triage_axes
Create Date: 2026-11-07
"""

from alembic import op
import sqlalchemy as sa


revision = "0058_agent_runtime"
down_revision = "0057_finding_triage_axes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_missions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("org_id", sa.String(length=36),
                  sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("actor", sa.String(length=255), nullable=False),
        sa.Column("actor_role", sa.String(length=16), nullable=False),
        sa.Column("goal", sa.Text(), nullable=False),
        sa.Column("capability", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("targets", sa.Text(), nullable=False),
        sa.Column("tools", sa.Text(), nullable=False),
        sa.Column("grant_id", sa.String(length=36), nullable=True),
        sa.Column("grant_level", sa.String(length=16), nullable=True),
        sa.Column("budget", sa.Text(), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=False),
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("run_id", sa.String(length=36),
                  sa.ForeignKey("ai_runs.id"), nullable=True),
        sa.Column("signature", sa.String(length=200), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(length=255), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_agent_missions_org", "agent_missions", ["org_id"])
    op.create_index("ix_agent_missions_status", "agent_missions", ["status"])

    op.create_table(
        "agent_tasks",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("mission_id", sa.String(length=36),
                  sa.ForeignKey("agent_missions.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("tools", sa.Text(), nullable=False),
        sa.Column("must_return", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("worker", sa.String(length=128), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("token_hash", sa.String(length=64), nullable=True),
        sa.Column("token_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result", sa.Text(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_agent_tasks_org", "agent_tasks", ["org_id"])
    op.create_index("ix_agent_tasks_mission", "agent_tasks", ["mission_id"])
    op.create_index("ix_agent_tasks_status", "agent_tasks", ["status"])
    op.create_index("ix_agent_tasks_token", "agent_tasks", ["token_hash"],
                    unique=True)

    op.create_table(
        "agent_task_events",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("task_id", sa.String(length=36),
                  sa.ForeignKey("agent_tasks.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("tool", sa.String(length=64), nullable=True),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("task_id", "seq", name="uq_agent_event_seq"),
    )
    op.create_index("ix_agent_task_events_org", "agent_task_events", ["org_id"])
    op.create_index("ix_agent_task_events_task", "agent_task_events", ["task_id"])


def downgrade() -> None:
    op.drop_index("ix_agent_task_events_task", table_name="agent_task_events")
    op.drop_index("ix_agent_task_events_org", table_name="agent_task_events")
    op.drop_table("agent_task_events")
    op.drop_index("ix_agent_tasks_token", table_name="agent_tasks")
    op.drop_index("ix_agent_tasks_status", table_name="agent_tasks")
    op.drop_index("ix_agent_tasks_mission", table_name="agent_tasks")
    op.drop_index("ix_agent_tasks_org", table_name="agent_tasks")
    op.drop_table("agent_tasks")
    op.drop_index("ix_agent_missions_status", table_name="agent_missions")
    op.drop_index("ix_agent_missions_org", table_name="agent_missions")
    op.drop_table("agent_missions")

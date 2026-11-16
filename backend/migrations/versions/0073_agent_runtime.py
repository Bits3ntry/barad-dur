"""agent runtime: runs, messages, artifacts, candidates and gate verdicts

The execution plane is already built (missions, tasks, claim, token, envelope). What was
missing is the layer above it: one row per agent execution (`agent_runs`), the non-linear
thread between them (`agent_messages`), the bytes they handle (`agent_artifacts`), and the
distinction between "the model proposed it" (`candidates`) and "we proved it"
(`gate_runs`). A candidate is never a finding; only a gate chain can promote it.

Also widens the existing rows: `ai_steps` learns which run and phase it belongs to and
whether its usage was priced; `agent_specs` learns who its parent is and which tools it
may use; `agent_events` learns which run line it belongs to and which message it replies
to; `agent_tasks` learns which task spawned it.

Revision ID: 0073_agent_runtime
Revises: 0072_finding_proof
Create Date: 2026-11-09
"""

from alembic import op
import sqlalchemy as sa


revision = "0073_agent_runtime"
down_revision = "0072_finding_proof"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("mission_id", sa.String(36), nullable=True),
        sa.Column("parent_run_id", sa.String(36), nullable=True),
        sa.Column("spec_slug", sa.String(64), nullable=False),
        sa.Column("thread", sa.String(96), nullable=True),
        sa.Column("status", sa.String(32), nullable=False, server_default="queued"),
        sa.Column("goal", sa.Text(), nullable=True),
        sa.Column("max_turns", sa.Integer(), nullable=True),
        sa.Column("turn_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cost_ceiling_usd", sa.Float(), nullable=True),
        sa.Column("cost_usd", sa.Float(), nullable=False, server_default="0"),
        sa.Column("tokens_in", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tokens_out", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("engine_task_id", sa.String(36), nullable=True),
        sa.Column("blocked_reason", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_agent_runs_org", "agent_runs", ["org_id"])
    op.create_index("ix_agent_runs_mission", "agent_runs", ["mission_id"])
    op.create_index("ix_agent_runs_parent", "agent_runs", ["parent_run_id"])
    op.create_index("ix_agent_runs_thread", "agent_runs", ["thread"])
    op.create_index("ix_agent_runs_status", "agent_runs", ["status"])

    op.create_table(
        "agent_messages",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("mission_id", sa.String(36), nullable=True),
        sa.Column("from_run", sa.String(36), nullable=True),
        sa.Column("to_run", sa.String(36), nullable=True),
        sa.Column("to_spec", sa.String(64), nullable=True),
        sa.Column("kind", sa.String(24), nullable=False, server_default="message"),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("reply_to", sa.String(36), nullable=True),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_agent_messages_mission", "agent_messages", ["mission_id"])
    op.create_index("ix_agent_messages_to_run", "agent_messages", ["to_run"])

    op.create_table(
        "agent_artifacts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("mission_id", sa.String(36), nullable=True),
        sa.Column("run_id", sa.String(36), nullable=True),
        sa.Column("task_id", sa.String(36), nullable=True),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=True),
        sa.Column("bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("storage", sa.String(255), nullable=True),
        sa.Column("meta", sa.Text(), nullable=True),
        sa.Column("produced_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_agent_artifacts_run", "agent_artifacts", ["run_id"])
    op.create_index("ix_agent_artifacts_mission", "agent_artifacts", ["mission_id"])
    op.create_index("ix_agent_artifacts_task", "agent_artifacts", ["task_id"])

    op.create_table(
        "candidates",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("mission_id", sa.String(36), nullable=True),
        sa.Column("run_id", sa.String(36), nullable=True),
        sa.Column("finding_id", sa.String(36), nullable=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(16), nullable=True),
        sa.Column("claim", sa.Text(), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("state", sa.String(24), nullable=False, server_default="proposed"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_candidates_org", "candidates", ["org_id"])
    op.create_index("ix_candidates_mission", "candidates", ["mission_id"])
    op.create_index("ix_candidates_state", "candidates", ["state"])

    op.create_table(
        "gate_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("candidate_id", sa.String(36), sa.ForeignKey("candidates.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("stage", sa.String(48), nullable=False),
        sa.Column("verdict", sa.String(16), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("evidence_ref", sa.String(120), nullable=True),
        sa.Column("cost_usd", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_gate_runs_candidate", "gate_runs", ["candidate_id"])
    op.create_index("ix_gate_runs_org", "gate_runs", ["org_id"])

    op.add_column("agent_events", sa.Column("run_ref", sa.String(36), nullable=True))
    op.add_column("agent_events", sa.Column("reply_to", sa.String(36), nullable=True))
    op.create_index("ix_agent_events_run_ref", "agent_events", ["run_ref"])

    op.add_column("agent_tasks", sa.Column("parent_task_id", sa.String(36), nullable=True))
    op.add_column("ai_steps", sa.Column("parent_run_id", sa.String(36), nullable=True))
    op.add_column("ai_steps", sa.Column("phase", sa.String(48), nullable=True))
    op.add_column("agent_specs", sa.Column("parent_slug", sa.String(64), nullable=True))
    op.add_column("agent_specs", sa.Column("allowed_tools", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("agent_specs", "allowed_tools")
    op.drop_column("agent_specs", "parent_slug")
    op.drop_column("ai_steps", "phase")
    op.drop_column("ai_steps", "parent_run_id")
    op.drop_column("agent_tasks", "parent_task_id")
    op.drop_index("ix_agent_events_run_ref", table_name="agent_events")
    op.drop_column("agent_events", "reply_to")
    op.drop_column("agent_events", "run_ref")
    op.drop_table("gate_runs")
    op.drop_table("candidates")
    op.drop_table("agent_artifacts")
    op.drop_table("agent_messages")
    op.drop_table("agent_runs")

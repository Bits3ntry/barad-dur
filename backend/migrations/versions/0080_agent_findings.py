"""findings carry the agent that produced them

A finding that came out of an autonomous run has to answer three questions the
scanner path never had to: which mission authorised it, which task decided it, and
which candidate the gates settled. Without those ids the trace exists in
`agent_task_events` and the finding cannot reach it, so the operator sees a claim
with no story behind it.

Revision ID: 0080_agent_findings
Revises: 0079_repeat_runs
Create Date: 2026-11-12
"""

from alembic import op
import sqlalchemy as sa


revision = "0080_agent_findings"
down_revision = "0079_repeat_runs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("findings") as batch:
        batch.add_column(sa.Column("agent_mission_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("agent_task_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("agent_candidate_id", sa.String(36), nullable=True))
        batch.create_index("ix_findings_agent_mission", ["agent_mission_id"])
        batch.create_index("ix_findings_agent_task", ["agent_task_id"])


def downgrade() -> None:
    with op.batch_alter_table("findings") as batch:
        batch.drop_index("ix_findings_agent_task")
        batch.drop_index("ix_findings_agent_mission")
        batch.drop_column("agent_candidate_id")
        batch.drop_column("agent_task_id")
        batch.drop_column("agent_mission_id")

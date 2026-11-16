"""a run can belong to a conversation

A6's first half: the channel merges `chat_turns` (what was said), `ai_steps` (what each
participant did) and `agent_task_events` (what the field agent saw). Without this column
a run cannot say which conversation it answered, so a mission started from a thread had
nowhere to appear.

Nullable on purpose: a run asked outside the channel (a direct `/ai/runs` call, a cycle
scan) is a real run with no thread, and giving it a fabricated session would be worse
than showing it only in the ledger.

Revision ID: 0085_ai_run_session
Revises: 0084_ai_prompts
"""

from alembic import op
import sqlalchemy as sa

revision = "0085_ai_run_session"
down_revision = "0084_ai_prompts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ai_runs", sa.Column("session_id", sa.String(36), nullable=True))
    op.create_foreign_key("fk_ai_runs_session", "ai_runs", "chat_sessions",
                          ["session_id"], ["id"])
    op.create_index("ix_ai_runs_session", "ai_runs", ["session_id"])


def downgrade() -> None:
    op.drop_index("ix_ai_runs_session", table_name="ai_runs")
    op.drop_constraint("fk_ai_runs_session", "ai_runs", type_="foreignkey")
    op.drop_column("ai_runs", "session_id")

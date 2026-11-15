"""keep the provider's own usage block, before knowing its shape

A flat subscription (opencode Go) meters an allowance instead of billing per token, and
its response reports that outside `prompt_tokens`/`completion_tokens`. Guessing the
field name would put a fabricated cost in a column nobody can audit, so the block is
stored verbatim and interpreted later — a measurement first, arithmetic second.

Revision ID: 0086_ai_step_usage
Revises: 0085_ai_run_session
"""

from alembic import op
import sqlalchemy as sa

revision = "0086_ai_step_usage"
down_revision = "0085_ai_run_session"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ai_steps", sa.Column("usage_json", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("ai_steps", "usage_json")

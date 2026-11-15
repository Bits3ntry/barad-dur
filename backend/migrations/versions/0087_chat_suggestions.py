"""the buttons under an answer travel with the turn

A suggestion is part of what the assistant said, not a piece of UI state: if the answer is
replayed tomorrow, the button it offered has to come back with it — or the reader sees an
affordance that vanished. The column keeps the validated list (see `ai/suggestions.py`),
so the screen never has to re-derive which of the model's ideas the platform can honour.

Revision ID: 0087_chat_suggestions
Revises: 0086_ai_step_usage
"""

from alembic import op
import sqlalchemy as sa

revision = "0087_chat_suggestions"
down_revision = "0086_ai_step_usage"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("chat_turns",
                  sa.Column("suggestions", sa.Text(), nullable=False,
                            server_default="[]"))


def downgrade() -> None:
    op.drop_column("chat_turns", "suggestions")

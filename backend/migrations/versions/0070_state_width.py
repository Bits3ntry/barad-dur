"""give the mission states room to be named

`awaiting_approval` is 17 characters and the column was varchar(16), so the gate could
not be written: Postgres raised StringDataRightTruncation on the insert. SQLite does not
enforce varchar length, which is why the suite passed and the container returned 500 —
a state name belongs in the column that stores it, not truncated on the way in.

Widening both status columns to 32 (missions and tasks share the vocabulary).

Revision ID: 0070_state_width
Revises: 0069_mission_approval
Create Date: 2026-11-09
"""

from alembic import op


revision = "0070_state_width"
down_revision = "0069_mission_approval"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE agent_missions ALTER COLUMN status TYPE VARCHAR(32)")
    op.execute("ALTER TABLE agent_tasks ALTER COLUMN status TYPE VARCHAR(32)")


def downgrade() -> None:
    op.execute("ALTER TABLE agent_tasks ALTER COLUMN status TYPE VARCHAR(16)")
    op.execute("ALTER TABLE agent_missions ALTER COLUMN status TYPE VARCHAR(16)")

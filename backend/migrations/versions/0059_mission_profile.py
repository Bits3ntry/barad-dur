"""profiles: a mission names who authorized it (F4, D42)

Angmar validates; Morgoth discovers and exploits. The lane and the capability have
to agree, so the profile is not decoration — it is the rule that decides which
capabilities a mission may ask for at all.

Backfill reads the capability: everything that exists today was `validate`.

Revision ID: 0059_mission_profile
Revises: 0058_agent_runtime
Create Date: 2026-11-07
"""

from alembic import op
import sqlalchemy as sa


revision = "0059_mission_profile"
down_revision = "0058_agent_runtime"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("agent_missions", sa.Column(
        "profile", sa.String(length=16), nullable=False,
        server_default="angmar"))
    op.create_index("ix_agent_missions_profile", "agent_missions", ["profile"])
    op.execute("""
        UPDATE agent_missions SET profile = 'morgoth'
        WHERE capability IN ('discover', 'exploit')
    """)


def downgrade() -> None:
    op.drop_index("ix_agent_missions_profile", table_name="agent_missions")
    op.drop_column("agent_missions", "profile")

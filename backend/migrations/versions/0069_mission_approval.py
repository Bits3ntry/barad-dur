"""the gate: who approved a mission, and when

A mission is the operator's authorization, so it now starts `awaiting_approval` and a
task cannot be dispatched until a human approves it. The two columns record that act —
"approved" is a fact with a name, not a status a script can flip silently.

Revision ID: 0069_mission_approval
Revises: 0068_agent_entry_tools
Create Date: 2026-11-09
"""

from alembic import op
import sqlalchemy as sa


revision = "0069_mission_approval"
down_revision = "0068_profile_origin_tools"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("agent_missions", sa.Column("approved_by", sa.String(255),
                                              nullable=True))
    op.add_column("agent_missions", sa.Column("approved_at",
                                              sa.DateTime(timezone=True),
                                              nullable=True))
    # The tool exists now, so the validator stops being a draft: the stored request
    # is what it replays, and a host without a grant is refused by the endpoint.
    op.execute("""
        UPDATE agent_specs
        SET tools = '["asset_fingerprint", "authorized_targets", "findings_search", '
                    '"deployment_chain", "probe.replay"]',
            status = 'active',
            updated_at = now()
        WHERE slug = 'validate.finding'
    """)


def downgrade() -> None:
    op.execute("""
        UPDATE agent_specs
        SET tools = '["asset_fingerprint", "authorized_targets", "findings_search", '
                    '"deployment_chain"]',
            status = 'draft'
        WHERE slug = 'validate.finding'
    """)
    op.drop_column("agent_missions", "approved_at")
    op.drop_column("agent_missions", "approved_by")

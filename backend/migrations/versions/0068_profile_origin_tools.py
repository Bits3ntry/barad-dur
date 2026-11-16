"""attacker profiles: where the actor comes from, and what they carry

OpenCTEM's designation asks three things (a name, a description, and where the
profile comes from) plus the tooling the actor is known for. Ours had only a name,
a description and ATT&CK techniques, which made every profile look like a custom
one and left the tools in prose.

  origin  custom | external | none   — who authored the profile
  tools   JSON list of tools/archetypes the actor is known to use (nmap,
          metasploit, commodity): free text because it is not a closed vocabulary,
          and a tool that is not in any catalogue still describes the actor.

Existing rows become `custom`: they were written by hand in this console.

Revision ID: 0068_profile_origin_tools
Revises: 0068_agent_entry_tools

Anchored on the tail another workstream landed while this revision was being written:
two heads would block every boot, and the chain is the contract.
Create Date: 2026-11-09
"""

from alembic import op
import sqlalchemy as sa


revision = "0068_profile_origin_tools"
down_revision = "0068_agent_entry_tools"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("attacker_profiles", sa.Column(
        "origin", sa.String(length=16), nullable=False, server_default="custom"))
    op.add_column("attacker_profiles", sa.Column("tools", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("attacker_profiles", "tools")
    op.drop_column("attacker_profiles", "origin")

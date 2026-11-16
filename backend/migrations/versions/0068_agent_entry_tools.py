"""give the catalogue its entry tools: fingerprint and authorized targets

`validate.finding` shipped declaring only read tools because the field tools did not
exist. Two of them now do — `asset_fingerprint` (what we know about an authorized
host) and `authorized_targets` (the hosts a grant actually covers) — and both are
`risk=read`, so they belong to the analyst and to the validator without widening
anyone's authority. `validate.finding` stays `draft`: `probe.replay` is still missing,
and a validator that cannot send the stored request is not a validator yet.

Data migration, no schema change.

Revision ID: 0068_agent_entry_tools
Revises: 0067_agent_specs
Create Date: 2026-11-09
"""

from alembic import op


revision = "0068_agent_entry_tools"
down_revision = "0067_agent_specs"
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.execute("""
        UPDATE agent_specs
        SET tools = '["asset_fingerprint", "authorized_targets", "findings_search", '
                    '"deployment_chain"]',
            updated_at = now()
        WHERE slug = 'validate.finding'
    """)
    op.execute("""
        UPDATE agent_specs
        SET tools = '["projects_list", "project_inventory", "components_impact", '
                    '"deployment_chain", "vulnerabilities_search", "findings_search", '
                    '"assets_search", "advisory_resolve", "intel_kev_catalog", '
                    '"asset_fingerprint", "authorized_targets"]',
            updated_at = now()
        WHERE slug = 'estate.analyst'
    """)


def downgrade() -> None:
    op.execute("""
        UPDATE agent_specs
        SET tools = '["asset_fingerprint", "authorized_targets"]'
        WHERE slug = 'validate.finding'
    """)
    op.execute("""
        UPDATE agent_specs
        SET tools = '["projects_list", "project_inventory", "components_impact", '
                    '"deployment_chain", "vulnerabilities_search", "findings_search", '
                    '"assets_search", "advisory_resolve", "intel_kev_catalog"]'
        WHERE slug = 'estate.analyst'
    """)

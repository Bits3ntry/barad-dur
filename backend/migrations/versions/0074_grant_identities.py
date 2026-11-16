"""two identities per grant, so a bypass can be proved instead of argued

An IDOR or an authorization bypass is confirmed by asking the same question twice with
two different principals and comparing the answers. That needs credentials, so they are
sealed with the platform key (same `secrets.seal` path as integration tokens) and never
returned by the API — only `label` and `last_used_at` leave the row.

Revision ID: 0074_grant_identities
Revises: 0073_agent_runtime
Create Date: 2026-11-09
"""

from alembic import op
import sqlalchemy as sa


revision = "0074_grant_identities"
down_revision = "0073_agent_runtime"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "grant_identities",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("grant_id", sa.String(36), sa.ForeignKey("scan_grants.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("label", sa.String(64), nullable=False),
        sa.Column("headers_cipher", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(),
                  nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_grant_identities_grant", "grant_identities", ["grant_id"])
    op.create_unique_constraint("uq_grant_identity_label", "grant_identities",
                                ["grant_id", "label"])


def downgrade() -> None:
    op.drop_constraint("uq_grant_identity_label", "grant_identities", type_="unique")
    op.drop_index("ix_grant_identities_grant", table_name="grant_identities")
    op.drop_table("grant_identities")

"""cycle kind: what exercise this window is

`sweep | campaign | pentest_external | pentest_internal | supply_chain |
ai_redteam`. The kind decides who produces the evidence and how the review and the
KPI are bucketed, so every existing row gets `sweep` — it is the honest reading of
a cycle created before the column existed: nobody declared a different exercise.

Revision ID: 0062_cycle_kind
Revises: 0061_cycle_intake
Create Date: 2026-11-09
"""

from alembic import op
import sqlalchemy as sa


revision = "0062_cycle_kind"
down_revision = "0061_cycle_intake"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("cycles", sa.Column(
        "kind", sa.String(length=24), nullable=False, server_default="sweep"))
    op.create_index("ix_cycles_kind", "cycles", ["kind"])


def downgrade() -> None:
    op.drop_index("ix_cycles_kind", table_name="cycles")
    op.drop_column("cycles", "kind")

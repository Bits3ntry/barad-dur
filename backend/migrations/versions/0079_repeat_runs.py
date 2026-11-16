"""repeat_runs: the chain that reproduced a finding, kept with its responses

A finding that says "POST /rest/user/login with this payload" is not reproducible
on its own when the endpoint needs a session, so Repeat executes an ordered chain
(login → extract token → the request the finding claims) through the same
authorization gate as a scan. This table keeps each execution: the steps as they
were written, the responses as they came back, and the variables that carried a
value from one step to the next.

Revision ID: 0079_repeat_runs
Revises: 0078_kev_sources
Create Date: 2026-11-11
"""

from alembic import op
import sqlalchemy as sa


revision = "0079_repeat_runs"
down_revision = "0078_kev_sources"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "repeat_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"),
                  nullable=False),
        sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id"),
                  nullable=True),
        sa.Column("actor", sa.String(255), nullable=True),
        sa.Column("result", sa.String(16), nullable=False, server_default="ok"),
        sa.Column("steps", sa.Text(), nullable=True),
        sa.Column("variables", sa.Text(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_repeat_runs_org", "repeat_runs", ["org_id"])
    op.create_index("ix_repeat_runs_finding", "repeat_runs", ["finding_id"])


def downgrade() -> None:
    op.drop_index("ix_repeat_runs_finding", table_name="repeat_runs")
    op.drop_index("ix_repeat_runs_org", table_name="repeat_runs")
    op.drop_table("repeat_runs")

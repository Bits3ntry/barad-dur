"""prompts as versions

The code string in `ai/specialists.py` stays the floor; this table holds the versions
a person wrote on top of it. One row per key may be `active`, which is what lets a step
record `intel.cve@3` and mean it.

Revision ID: 0084_ai_prompts
Revises: 0083_ai_settings_reconcile
"""

from alembic import op
import sqlalchemy as sa

revision = "0084_ai_prompts"
down_revision = "0083_ai_settings_reconcile"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_prompts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("key", sa.String(64), nullable=False, index=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="draft",
                  index=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(255), nullable=True),
        sa.Column("activated_by", sa.String(255), nullable=True),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("key", "version", name="uq_ai_prompt_version"),
    )
    # The registry is per deployment, like the provider list, so no rows are seeded:
    # an empty table answers with the code floor, and only an override is a row.
    op.create_index("ix_ai_prompts_key_status", "ai_prompts", ["key", "status"])


def downgrade() -> None:
    op.drop_index("ix_ai_prompts_key_status", table_name="ai_prompts")
    op.drop_table("ai_prompts")

"""measure what the AI spends, including the part the provider compresses

`cached_tokens` is the provider's prompt-cache hit: a saving that is not recorded is a
saving nobody can claim. `token_budget` is a per-run safety ceiling — nullable on
purpose, because a run ceiling that is too tight is a capacity cut disguised as a
saving; the profile decides when to set it.

Revision ID: 0075_ai_metrics
Revises: 0074_grant_identities
Create Date: 2026-11-09
"""

from alembic import op
import sqlalchemy as sa


revision = "0075_ai_metrics"
down_revision = "0074_grant_identities"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ai_steps", sa.Column("cached_tokens", sa.Integer(),
                                        nullable=False, server_default="0"))
    op.add_column("ai_runs", sa.Column("token_budget", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("ai_runs", "token_budget")
    op.drop_column("ai_steps", "cached_tokens")

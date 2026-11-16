"""AI harness: providers, budget, runs and steps (F1)

Revision ID: 0054_ai_harness
Revises: 0053_device_authorizations
Create Date: 2026-11-07

Configuration is deployment-wide (D17); runs and steps carry `org_id` because the
question is about one estate. The provider key lives only as a sealed cipher — the
plaintext is never a column (D9).
"""

from alembic import op
import sqlalchemy as sa


revision = "0054_ai_harness"
down_revision = "0053_device_authorizations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_providers",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False,
                  server_default="openai-compatible"),
        sa.Column("base_url", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("model", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("secret_cipher", sa.Text(), nullable=True),
        sa.Column("price_in", sa.Float(), nullable=True),
        sa.Column("price_out", sa.Float(), nullable=True),
        sa.Column("max_output_tokens", sa.Integer(), nullable=False, server_default="1024"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("is_default", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("name", name="uq_ai_provider_name"),
    )

    op.create_table(
        "ai_settings",
        sa.Column("id", sa.String(length=16), primary_key=True),
        sa.Column("monthly_token_cap", sa.Integer(), nullable=True),
        sa.Column("monthly_cost_cap", sa.Float(), nullable=True),
        sa.Column("max_steps", sa.Integer(), nullable=False, server_default="6"),
        sa.Column("max_specialists", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("redteam_allowed", sa.Boolean(), nullable=False,
                  server_default=sa.false()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_by", sa.String(length=320), nullable=True),
    )
    op.execute("INSERT INTO ai_settings (id) VALUES ('default')")

    op.create_table(
        "ai_runs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("org_id", sa.String(length=36), sa.ForeignKey("organizations.id"),
                  nullable=False),
        sa.Column("actor", sa.String(length=255), nullable=False, server_default="system"),
        sa.Column("actor_role", sa.String(length=16), nullable=False, server_default="viewer"),
        sa.Column("question", sa.Text(), nullable=False),
        sa.Column("mode", sa.String(length=16), nullable=False, server_default="ask"),
        sa.Column("status", sa.String(length=24), nullable=False, server_default="running"),
        sa.Column("stop_reason", sa.String(length=64), nullable=True),
        sa.Column("provider_id", sa.String(length=36), sa.ForeignKey("ai_providers.id"),
                  nullable=True),
        sa.Column("model", sa.String(length=128), nullable=True),
        sa.Column("answer", sa.Text(), nullable=True),
        sa.Column("steps", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tool_calls", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tokens_in", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tokens_out", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cost_usd", sa.Float(), nullable=True),
        sa.Column("price_known", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_ai_runs_org_id", "ai_runs", ["org_id"])
    op.create_index("ix_ai_runs_status", "ai_runs", ["status"])
    op.create_index("ix_ai_runs_org_started", "ai_runs", ["org_id", "started_at"])

    op.create_table(
        "ai_steps",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36),
                  sa.ForeignKey("ai_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False,
                  server_default="orchestrator"),
        sa.Column("prompt_version", sa.String(length=32), nullable=True),
        sa.Column("tool_calls", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("handoff", sa.Text(), nullable=True),
        sa.Column("tokens_in", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tokens_out", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cost_usd", sa.Float(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("run_id", "seq", name="uq_ai_step_seq"),
    )
    op.create_index("ix_ai_steps_org_id", "ai_steps", ["org_id"])
    op.create_index("ix_ai_steps_run_id", "ai_steps", ["run_id"])


def downgrade() -> None:
    op.drop_index("ix_ai_steps_run_id", table_name="ai_steps")
    op.drop_index("ix_ai_steps_org_id", table_name="ai_steps")
    op.drop_table("ai_steps")
    op.drop_index("ix_ai_runs_org_started", table_name="ai_runs")
    op.drop_index("ix_ai_runs_status", table_name="ai_runs")
    op.drop_index("ix_ai_runs_org_id", table_name="ai_runs")
    op.drop_table("ai_runs")
    op.drop_table("ai_settings")
    op.drop_table("ai_providers")

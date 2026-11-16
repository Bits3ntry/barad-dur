"""Chat sessions: the record, the prompt, and the compaction between them (F1)

Revision ID: 0055_chat_sessions
Revises: 0054_ai_harness
Create Date: 2026-11-07

`chat_turns` is the record and is never pruned. The prompt is assembled from
`brief + pins + last K turns`, so compression changes what the model sees and not
what the operator can read (§4c, D67/D68).
"""

from alembic import op
import sqlalchemy as sa


revision = "0055_chat_sessions"
down_revision = "0054_ai_harness"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "chat_sessions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("org_id", sa.String(length=36), sa.ForeignKey("organizations.id"),
                  nullable=False),
        sa.Column("created_by", sa.String(length=320), nullable=False,
                  server_default="system"),
        sa.Column("title", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("subject_kind", sa.String(length=32), nullable=True),
        sa.Column("subject_id", sa.String(length=64), nullable=True),
        sa.Column("profile_key", sa.String(length=32), nullable=False,
                  server_default="palantir"),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="idle"),
        sa.Column("brief", sa.Text(), nullable=True),
        sa.Column("brief_version", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("brief_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_turn_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_chat_sessions_org_id", "chat_sessions", ["org_id"])
    op.create_index("ix_chat_sessions_status", "chat_sessions", ["status"])
    op.create_index("ix_chat_sessions_org_turn", "chat_sessions",
                    ["org_id", "last_turn_at"])

    op.create_table(
        "chat_turns",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("session_id", sa.String(length=36),
                  sa.ForeignKey("chat_sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("author", sa.String(length=320), nullable=True),
        sa.Column("profile_key", sa.String(length=32), nullable=True),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("citations", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("run_id", sa.String(length=36), sa.ForeignKey("ai_runs.id"),
                  nullable=True),
        sa.Column("tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("session_id", "seq", name="uq_chat_turn_seq"),
    )
    op.create_index("ix_chat_turns_org_id", "chat_turns", ["org_id"])
    op.create_index("ix_chat_turns_session_id", "chat_turns", ["session_id"])

    op.create_table(
        "chat_pins",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("session_id", sa.String(length=36),
                  sa.ForeignKey("chat_sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("turn_id", sa.String(length=36),
                  sa.ForeignKey("chat_turns.id", ondelete="CASCADE"), nullable=True),
        sa.Column("note", sa.String(length=512), nullable=True),
        sa.Column("created_by", sa.String(length=320), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_chat_pins_org_id", "chat_pins", ["org_id"])
    op.create_index("ix_chat_pins_session_id", "chat_pins", ["session_id"])


def downgrade() -> None:
    op.drop_index("ix_chat_pins_session_id", table_name="chat_pins")
    op.drop_index("ix_chat_pins_org_id", table_name="chat_pins")
    op.drop_table("chat_pins")
    op.drop_index("ix_chat_turns_session_id", table_name="chat_turns")
    op.drop_index("ix_chat_turns_org_id", table_name="chat_turns")
    op.drop_table("chat_turns")
    op.drop_index("ix_chat_sessions_org_turn", table_name="chat_sessions")
    op.drop_index("ix_chat_sessions_status", table_name="chat_sessions")
    op.drop_index("ix_chat_sessions_org_id", table_name="chat_sessions")
    op.drop_table("chat_sessions")

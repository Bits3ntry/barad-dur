"""a cycle carries its notes and its documents

A cycle is a campaign: it has a brief, the client's scope letter, the pentest report
that started it. Notes are free text on the cycle; documents are bytes we keep, not
a link that rots — the report is the evidence a review is written from.

`media_type` is stored as received, never guessed: a wrong type on a PDF makes the
download open as text and the reviewer think the upload failed.

Revision ID: 0071_cycle_documents
Revises: 0070_state_width
Create Date: 2026-11-09
"""

from alembic import op
import sqlalchemy as sa


revision = "0071_cycle_documents"
down_revision = "0070_state_width"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("cycles", sa.Column("notes", sa.Text(), nullable=True))

    op.create_table(
        "cycle_documents",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("org_id", sa.String(length=36), sa.ForeignKey("organizations.id"),
                  nullable=False),
        sa.Column("cycle_id", sa.String(length=36),
                  sa.ForeignKey("cycles.id", ondelete="CASCADE"), nullable=False),
        sa.Column("filename", sa.String(length=512), nullable=False),
        sa.Column("media_type", sa.String(length=128), nullable=True),
        sa.Column("size", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("data", sa.LargeBinary(), nullable=False),
        sa.Column("uploaded_by", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_cycle_documents_cycle", "cycle_documents", ["cycle_id"])
    op.create_index("ix_cycle_documents_org", "cycle_documents", ["org_id"])


def downgrade() -> None:
    op.drop_index("ix_cycle_documents_org", table_name="cycle_documents")
    op.drop_index("ix_cycle_documents_cycle", table_name="cycle_documents")
    op.drop_table("cycle_documents")
    op.drop_column("cycles", "notes")

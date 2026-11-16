"""organization_members: a person may work in more than one organisation

`users.org_id` was doing double duty as "the person's account" and "the only
organisation they can see", so switching was not a UI problem — there was
nothing to switch to. This adds the seat and backfills one per existing user,
carrying their current role so nobody gains or loses a permission.

Revision ID: 0077_org_members
Revises: 0076_scan_workflows
Create Date: 2026-11-10
"""

import datetime
from uuid import uuid4

from alembic import op
import sqlalchemy as sa


revision = "0077_org_members"
down_revision = "0076_scan_workflows"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "organization_members",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"),
                  nullable=False),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("role", sa.String(16), nullable=False, server_default="viewer"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "user_id", name="uq_org_members"),
    )
    op.create_index("ix_org_members_org", "organization_members", ["org_id"])
    op.create_index("ix_org_members_user", "organization_members", ["user_id"])

    # Backfill in Python: the same statement runs on Postgres and on the SQLite
    # databases the tests build, and there is no server-side uuid to rely on.
    bind = op.get_bind()
    rows = bind.execute(sa.text("SELECT id, org_id, role FROM users")).fetchall()
    now = datetime.datetime.now(datetime.timezone.utc)
    for user_id, org_id, role in rows:
        bind.execute(
            sa.text("INSERT INTO organization_members (id, org_id, user_id, role, created_at) "
                    "VALUES (:id, :org_id, :user_id, :role, :created_at)"),
            {"id": uuid4().hex, "org_id": org_id, "user_id": user_id,
             "role": role or "viewer", "created_at": now})


def downgrade() -> None:
    op.drop_index("ix_org_members_user", table_name="organization_members")
    op.drop_index("ix_org_members_org", table_name="organization_members")
    op.drop_table("organization_members")

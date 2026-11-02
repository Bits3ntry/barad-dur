"""Migration 0042: optional TOTP second factor per user.

The secret is stored when enrolment starts; `totp_enabled_at` is what makes it
required at login. Challenges and recovery codes are separate tables so a
half-finished enrolment can never lock anyone out.
"""
from alembic import op
import sqlalchemy as sa

revision = "0042_user_mfa"
down_revision = "0041_analysis_origin"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("totp_secret", sa.String(64), nullable=True))
        batch.add_column(sa.Column("totp_enabled_at", sa.DateTime(timezone=True),
                                   nullable=True))

    op.create_table(
        "mfa_challenges",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"),
                  nullable=False),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index("ix_mfa_challenges_token", "mfa_challenges", ["token_hash"],
                    unique=True)
    op.create_index("ix_mfa_challenges_user", "mfa_challenges", ["user_id"])

    op.create_table(
        "mfa_recovery_codes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"),
                  nullable=False),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("code_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_mfa_recovery_user", "mfa_recovery_codes", ["user_id"])
    op.create_index("ix_mfa_recovery_hash", "mfa_recovery_codes", ["code_hash"])


def downgrade() -> None:
    op.drop_index("ix_mfa_recovery_hash", table_name="mfa_recovery_codes")
    op.drop_index("ix_mfa_recovery_user", table_name="mfa_recovery_codes")
    op.drop_table("mfa_recovery_codes")
    op.drop_index("ix_mfa_challenges_user", table_name="mfa_challenges")
    op.drop_index("ix_mfa_challenges_token", table_name="mfa_challenges")
    op.drop_table("mfa_challenges")
    with op.batch_alter_table("users") as batch:
        batch.drop_column("totp_enabled_at")
        batch.drop_column("totp_secret")

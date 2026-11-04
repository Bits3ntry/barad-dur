"""Migration 0043: onboarding — organization profile, invitations, teams, connections.

Additive only. Each table is new; the organization gains four nullable columns,
so an existing installation upgrades without touching a single row.

`integration_connections.secret_cipher` stores the provider credential already
encrypted with the platform key (see `app/secrets.py`); the plaintext never
reaches the database.
"""
from alembic import op
import sqlalchemy as sa

revision = "0043_onboarding"
down_revision = "0042_user_mfa"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("organizations") as batch:
        batch.add_column(sa.Column("description", sa.Text(), nullable=True))
        batch.add_column(sa.Column("website", sa.String(255), nullable=True))
        batch.add_column(sa.Column("logo", sa.Text(), nullable=True))
        batch.add_column(sa.Column("onboarding_completed_at",
                                   sa.DateTime(timezone=True), nullable=True))

    op.create_table(
        "teams",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"),
                  nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(320), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("org_id", "name", name="uq_teams_name"),
    )

    op.create_table(
        "org_invitations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"),
                  nullable=False),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("role", sa.String(16), nullable=False, server_default="analyst"),
        sa.Column("team_id", sa.String(36), sa.ForeignKey("teams.id"), nullable=True),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("invited_by", sa.String(320), nullable=True),
        sa.Column("display_name", sa.String(255), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_delivery", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("org_id", "email", name="uq_org_invitations_email"),
    )
    op.create_index("ix_org_invitations_token_hash", "org_invitations",
                    ["token_hash"], unique=True)

    op.create_table(
        "team_members",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"),
                  nullable=False),
        sa.Column("team_id", sa.String(36), sa.ForeignKey("teams.id"), nullable=False),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("added_by", sa.String(320), nullable=True),
        sa.UniqueConstraint("team_id", "user_id", name="uq_team_members_pair"),
    )
    op.create_index("ix_team_members_team", "team_members", ["team_id"])
    op.create_index("ix_team_members_user", "team_members", ["user_id"])

    op.create_table(
        "integration_connections",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"),
                  nullable=False),
        sa.Column("kind", sa.String(16), nullable=False, server_default="scm"),
        sa.Column("provider", sa.String(32), nullable=False, server_default="github"),
        sa.Column("label", sa.String(128), nullable=True),
        sa.Column("base_url", sa.String(255), nullable=False, server_default=""),
        sa.Column("account", sa.String(255), nullable=True),
        sa.Column("secret_cipher", sa.Text(), nullable=False),
        sa.Column("config", sa.Text(), nullable=True),
        sa.Column("access", sa.String(16), nullable=False, server_default="read"),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(320), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("org_id", "kind", "provider", "base_url",
                            name="uq_integration_connections_target"),
    )

    op.create_table(
        "platform_secrets",
        sa.Column("name", sa.String(64), primary_key=True),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("platform_secrets")
    op.drop_table("integration_connections")
    op.drop_index("ix_team_members_user", table_name="team_members")
    op.drop_index("ix_team_members_team", table_name="team_members")
    op.drop_table("team_members")
    op.drop_index("ix_org_invitations_token_hash", table_name="org_invitations")
    op.drop_table("org_invitations")
    op.drop_table("teams")
    with op.batch_alter_table("organizations") as batch:
        batch.drop_column("onboarding_completed_at")
        batch.drop_column("logo")
        batch.drop_column("website")
        batch.drop_column("description")

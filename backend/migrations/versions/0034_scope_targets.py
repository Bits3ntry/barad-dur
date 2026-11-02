"""Migration 0034: scope targets become declarative records.

Adds the fields the Scope screen owes a reader (reason, owner, provenance,
validity, restrictions, capabilities, wildcard apex rule) and the link from a
concrete target to its canonical asset. Existing rows keep working: provenance
defaults to `manual` and capabilities are backfilled with the type default, so
no row silently loses the capability it implicitly had.
"""
from alembic import op
import sqlalchemy as sa

revision = "0034_scope_targets"
down_revision = "0033_v0_inventory"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("scope_targets") as batch:
        batch.add_column(sa.Column("reason", sa.Text(), nullable=True))
        batch.add_column(sa.Column("owner", sa.String(255), nullable=True))
        batch.add_column(sa.Column("source", sa.String(32), nullable=False,
                                   server_default="manual"))
        batch.add_column(sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("restrictions", sa.JSON(), nullable=False,
                                   server_default="[]"))
        batch.add_column(sa.Column("capabilities", sa.JSON(), nullable=False,
                                   server_default="[]"))
        batch.add_column(sa.Column("include_apex", sa.Boolean(), nullable=False,
                                   server_default=sa.false()))
        batch.add_column(sa.Column("asset_id", sa.String(36),
                                   sa.ForeignKey("assets.id"), nullable=True))
    op.create_index("ix_scope_targets_owner", "scope_targets", ["owner"])
    op.create_index("ix_scope_targets_asset", "scope_targets", ["asset_id"])

    # Backfill the capability each type used to imply; an empty list would read
    # as "declared but permits nothing", which is a different statement.
    op.execute(
        "UPDATE scope_targets SET capabilities = '[\"passive_discovery\"]'::json "
        "WHERE target_type IN ('domain', 'host', 'ip', 'cidr', 'url', 'service', 'api')")
    op.execute(
        "UPDATE scope_targets SET capabilities = '[\"code_analysis\"]'::json "
        "WHERE target_type = 'repository'")

    with op.batch_alter_table("scope_exclusions") as batch:
        batch.add_column(sa.Column("owner", sa.String(255), nullable=True))
        batch.add_column(sa.Column("source", sa.String(32), nullable=False,
                                   server_default="manual"))
        batch.add_column(sa.Column("status", sa.String(32), nullable=False,
                                   server_default="active"))
        batch.add_column(sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("scope_exclusions") as batch:
        batch.drop_column("expires_at")
        batch.drop_column("status")
        batch.drop_column("source")
        batch.drop_column("owner")

    op.drop_index("ix_scope_targets_asset", table_name="scope_targets")
    op.drop_index("ix_scope_targets_owner", table_name="scope_targets")
    with op.batch_alter_table("scope_targets") as batch:
        batch.drop_column("asset_id")
        batch.drop_column("include_apex")
        batch.drop_column("capabilities")
        batch.drop_column("restrictions")
        batch.drop_column("valid_until")
        batch.drop_column("valid_from")
        batch.drop_column("source")
        batch.drop_column("owner")
        batch.drop_column("reason")

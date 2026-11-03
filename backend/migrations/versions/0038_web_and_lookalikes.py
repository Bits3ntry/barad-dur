"""Migration 0038: web surface and lookalike domains.

Both are observed external surface: a path is an endpoint with an explicit state
(candidate / observed / confirmed_finding / excluded / not_evaluated), and a
lookalike is a watched or impersonating domain whose registration state is
`unknown` until evidence says otherwise. Neither grants any authorization.
"""
from alembic import op
import sqlalchemy as sa

revision = "0038_web_and_lookalikes"
down_revision = "0037_attack_surface"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "web_endpoints",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id"), nullable=True),
        sa.Column("origin", sa.String(512), nullable=False),
        sa.Column("path", sa.String(1024), nullable=False),
        sa.Column("method", sa.String(16), nullable=False, server_default="GET"),
        sa.Column("state", sa.String(24), nullable=False, server_default="candidate"),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("discovery_source", sa.String(64), nullable=True),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "origin", "path", "method",
                            name="uq_web_endpoint_identity"),
    )
    op.create_index("ix_web_endpoints_org", "web_endpoints", ["org_id"])
    op.create_index("ix_web_endpoints_origin", "web_endpoints", ["origin"])
    op.create_index("ix_web_endpoints_state", "web_endpoints", ["state"])
    op.create_index("ix_web_endpoints_asset", "web_endpoints", ["asset_id"])

    op.create_table(
        "lookalike_domains",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("root_domain", sa.String(255), nullable=False),
        sa.Column("candidate", sa.String(255), nullable=False),
        sa.Column("similarity", sa.String(32), nullable=True),
        sa.Column("state", sa.String(24), nullable=False, server_default="candidate"),
        sa.Column("registration_evidence", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("dns", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("mx", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("certificates", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("registration_state", sa.String(24), nullable=False,
                  server_default="unknown"),
        sa.Column("review_reason", sa.Text(), nullable=True),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "root_domain", "candidate",
                            name="uq_lookalike_identity"),
    )
    op.create_index("ix_lookalikes_org", "lookalike_domains", ["org_id"])
    op.create_index("ix_lookalikes_root", "lookalike_domains", ["root_domain"])
    op.create_index("ix_lookalikes_state", "lookalike_domains", ["state"])


def downgrade() -> None:
    op.drop_index("ix_lookalikes_state", table_name="lookalike_domains")
    op.drop_index("ix_lookalikes_root", table_name="lookalike_domains")
    op.drop_index("ix_lookalikes_org", table_name="lookalike_domains")
    op.drop_table("lookalike_domains")
    op.drop_index("ix_web_endpoints_asset", table_name="web_endpoints")
    op.drop_index("ix_web_endpoints_state", table_name="web_endpoints")
    op.drop_index("ix_web_endpoints_origin", table_name="web_endpoints")
    op.drop_index("ix_web_endpoints_org", table_name="web_endpoints")
    op.drop_table("web_endpoints")

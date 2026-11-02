"""Migration 0037: observations, exposure events and their decisions.

Observations carry the coverage they were collected with, so a change comparison
can refuse to treat a failed collection as "closed port" or "host gone".
Exposure events have a stable identity and a decision history; the event is the
condition under management, the decisions are what people did about it.
"""
from alembic import op
import sqlalchemy as sa

revision = "0037_attack_surface"
down_revision = "0036_analysis_material"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "observations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id"), nullable=True),
        sa.Column("kind", sa.String(24), nullable=False),
        sa.Column("subject", sa.String(1024), nullable=False),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(16), nullable=True),
        sa.Column("value", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("source", sa.String(64), nullable=False, server_default="import"),
        sa.Column("coverage", sa.String(16), nullable=False, server_default="full"),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_observations_org", "observations", ["org_id"])
    op.create_index("ix_observations_asset_kind", "observations",
                    ["asset_id", "kind", "observed_at"])

    op.create_table(
        "exposure_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("assets.id"), nullable=True),
        sa.Column("stable_key", sa.String(255), nullable=False),
        sa.Column("kind", sa.String(24), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("severity", sa.String(32), nullable=True),
        sa.Column("source", sa.String(64), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.String(24), nullable=False, server_default="open"),
        sa.Column("decision_reason", sa.Text(), nullable=True),
        sa.Column("decided_by", sa.String(255), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("accepted_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reopen_policy", sa.String(32), nullable=False,
                  server_default="on_new_observation"),
        sa.Column("occurrences", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("evidence", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "stable_key", name="uq_exposure_key"),
    )
    op.create_index("ix_exposure_events_org", "exposure_events", ["org_id"])
    op.create_index("ix_exposure_events_state", "exposure_events", ["state"])
    op.create_index("ix_exposure_events_kind", "exposure_events", ["kind"])
    op.create_index("ix_exposure_events_asset", "exposure_events", ["asset_id"])

    op.create_table(
        "exposure_decisions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("event_id", sa.String(36),
                  sa.ForeignKey("exposure_events.id", ondelete="CASCADE"), nullable=False),
        sa.Column("action", sa.String(24), nullable=False),
        sa.Column("from_state", sa.String(24), nullable=True),
        sa.Column("to_state", sa.String(24), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("actor", sa.String(255), nullable=True),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_exposure_decisions_event", "exposure_decisions", ["event_id"])


def downgrade() -> None:
    op.drop_index("ix_exposure_decisions_event", table_name="exposure_decisions")
    op.drop_table("exposure_decisions")
    op.drop_index("ix_exposure_events_asset", table_name="exposure_events")
    op.drop_index("ix_exposure_events_kind", table_name="exposure_events")
    op.drop_index("ix_exposure_events_state", table_name="exposure_events")
    op.drop_index("ix_exposure_events_org", table_name="exposure_events")
    op.drop_table("exposure_events")
    op.drop_index("ix_observations_asset_kind", table_name="observations")
    op.drop_index("ix_observations_org", table_name="observations")
    op.drop_table("observations")

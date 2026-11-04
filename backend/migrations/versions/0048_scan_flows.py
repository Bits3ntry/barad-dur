"""v01 scan flows: jobs become flows, and every flow owns a timeline.

Additive only. The old orchestration columns stay where they are: the claim/lease
path is retired in a later slice, and dropping columns first would break the
history the Jobs screen is about to read.

Revision ID: 0048_scan_flows
Revises: 0047_component_versions
"""
from alembic import op
import sqlalchemy as sa

revision = "0048_scan_flows"
down_revision = "0047_component_versions"
branch_labels = None
depends_on = None

_JOB_COLUMNS = [
    ("origin", sa.String(16), "console"),
    ("executor", sa.String(16), "shauron"),
    ("tasks", sa.Text(), "[]"),
    ("subject", sa.Text(), "{}"),
    ("contract_version", sa.String(32), None),
    ("evidence_state", sa.String(16), "none"),
    ("upload_token_hash", sa.String(64), None),
    ("revival_count", sa.Integer(), "0"),
]


def upgrade() -> None:
    for name, column_type, default in _JOB_COLUMNS:
        op.add_column("scan_jobs", sa.Column(
            name, column_type, nullable=default is None,
            server_default=default))
    for name in ("ticket_json", "daemon_url"):
        op.add_column("scan_jobs", sa.Column(name, sa.Text(), nullable=True))
    for name in ("deadline_at", "last_event_at", "revived_at", "cancelled_at"):
        op.add_column("scan_jobs", sa.Column(
            name, sa.DateTime(timezone=True), nullable=True))

    op.create_table(
        "scan_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"),
                  nullable=False, index=True),
        sa.Column("job_id", sa.String(36),
                  sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("source", sa.String(16), nullable=False, server_default="platform"),
        sa.Column("actor", sa.String(255), nullable=True),
        sa.Column("host", sa.String(255), nullable=True),
        sa.Column("at_server", sa.DateTime(timezone=True), nullable=False),
        sa.Column("at_client", sa.DateTime(timezone=True), nullable=True),
        sa.Column("detail", sa.Text(), nullable=False, server_default="{}"),
        sa.UniqueConstraint("job_id", "seq", name="uq_scan_event_seq"),
    )
    op.create_index("ix_scan_events_job", "scan_events", ["job_id", "seq"])

    # Evidence knows which flow produced it. NULL keeps plain imports working.
    op.add_column("analysis_runs",
                  sa.Column("scan_job_id", sa.String(36),
                            sa.ForeignKey("scan_jobs.id"), nullable=True))
    op.create_index("ix_analysis_runs_scan_job", "analysis_runs", ["scan_job_id"])
    op.add_column("sbom_imports",
                  sa.Column("scan_job_id", sa.String(36),
                            sa.ForeignKey("scan_jobs.id"), nullable=True))
    op.create_index("ix_sbom_imports_scan_job", "sbom_imports", ["scan_job_id"])


def downgrade() -> None:
    op.drop_index("ix_sbom_imports_scan_job", table_name="sbom_imports")
    op.drop_column("sbom_imports", "scan_job_id")
    op.drop_index("ix_analysis_runs_scan_job", table_name="analysis_runs")
    op.drop_column("analysis_runs", "scan_job_id")

    op.drop_index("ix_scan_events_job", table_name="scan_events")
    op.drop_table("scan_events")

    for name in ("deadline_at", "last_event_at", "revived_at", "cancelled_at",
                 "ticket_json", "daemon_url"):
        op.drop_column("scan_jobs", name)
    for name, _type, _default in reversed(_JOB_COLUMNS):
        op.drop_column("scan_jobs", name)

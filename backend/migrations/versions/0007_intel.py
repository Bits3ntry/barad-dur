"""B3: intelligence catalog — CISA KEV + EPSS scores, VEX statements, reconcile.

Revision ID: 0007_intel
Revises: 0006_identity_audit
Create Date: 2026-10-30
"""
from alembic import op
import sqlalchemy as sa

revision = "0007_intel"
down_revision = "0006_identity_audit"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "kev_entries",
        sa.Column("cve_id", sa.String(32), primary_key=True),
        sa.Column("title", sa.Text, nullable=True),
        sa.Column("date_added", sa.String(32), nullable=True),
        sa.Column("due_date", sa.String(32), nullable=True),
        sa.Column("source", sa.String(255), nullable=True),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "epss_scores",
        sa.Column("cve_id", sa.String(32), primary_key=True),
        sa.Column("epss", sa.String(16), nullable=False),
        sa.Column("percentile", sa.String(16), nullable=True),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "vex_statements",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("statement", sa.Text, nullable=False),
        sa.Column("author", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_vex_finding", "vex_statements", ["finding_id"])
    op.add_column("vulnerabilities", sa.Column("cve_id", sa.String(32), nullable=True))
    op.create_index("ix_vulnerabilities_cve", "vulnerabilities", ["cve_id"])


def downgrade() -> None:
    op.drop_index("ix_vulnerabilities_cve", table_name="vulnerabilities")
    op.drop_column("vulnerabilities", "cve_id")
    op.drop_index("ix_vex_finding", table_name="vex_statements")
    op.drop_table("vex_statements")
    op.drop_table("epss_scores")
    op.drop_table("kev_entries")

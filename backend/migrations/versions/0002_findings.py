"""F1: vulnerability catalog and findings (kind=vulnerability for now).

Revision ID: 0002_findings
Revises: 0001_core
Create Date: 2026-10-30
"""
from alembic import op
import sqlalchemy as sa

revision = "0002_findings"
down_revision = "0001_core"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        # Global catalog: no org scoping, like the reference platform's
        # vulnerabilities table; findings reference it by id.
        "vulnerabilities",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("source_id", sa.String(255), nullable=False, unique=True),
        sa.Column("source", sa.String(32), nullable=False, default="osv"),
        sa.Column("cve_id", sa.String(32), nullable=True),
        sa.Column("title", sa.String(1024), nullable=True),
        sa.Column("severity", sa.String(32), nullable=True),
        sa.Column("cvss_vector", sa.String(255), nullable=True),
        sa.Column("url", sa.String(1024), nullable=True),
        sa.Column("published", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified", sa.DateTime(timezone=True), nullable=True),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_vulnerabilities_cve_id", "vulnerabilities", ["cve_id"])
    op.create_table(
        "findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("fingerprint", sa.String(128), nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("title", sa.String(1024), nullable=True),
        sa.Column("detail", sa.Text, nullable=True),
        sa.Column("severity", sa.String(32), nullable=True),
        sa.Column("url", sa.String(1024), nullable=True),
        sa.Column("component_id", sa.String(36),
                  sa.ForeignKey("components.id"), nullable=True),
        sa.Column("vulnerability_id", sa.String(36),
                  sa.ForeignKey("vulnerabilities.id"), nullable=True),
        sa.Column("status", sa.String(32), nullable=False, default="open"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "fingerprint", name="uq_findings_org_fingerprint"),
    )
    op.create_index("ix_findings_kind", "findings", ["kind"])
    op.create_index("ix_findings_fingerprint", "findings", ["fingerprint"])


def downgrade() -> None:
    op.drop_table("findings")
    op.drop_table("vulnerabilities")

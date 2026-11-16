"""one triage queue: origin, proof and impact as separate axes (F3, D29–D30)

Two worlds become one queue. `findings` gains where a row came from, who triaged
it, how strong the proof is and how far exploitation got — four independent facts,
because collapsing them into one ordered enum implied exploitation is required to
validate a finding, which is the opposite of how applicability work ends.

Backfill keeps the estate's numbers still: every existing row is
`origin=scanner, triage_status=triaged, evidence_level=observed, exploit_state=none`.
Nothing that was counted yesterday stops being counted today because of a migration.

Revision ID: 0057_finding_triage_axes
Revises: 0056_asset_geo
Create Date: 2026-11-07
"""

from alembic import op
import sqlalchemy as sa


revision = "0057_finding_triage_axes"
down_revision = "0056_asset_geo"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column(
        "asset_id", sa.String(length=36), nullable=True))
    op.create_foreign_key("fk_findings_asset", "findings", "assets",
                          ["asset_id"], ["id"])
    op.create_index("ix_findings_asset_id", "findings", ["asset_id"])

    op.add_column("findings", sa.Column(
        "origin", sa.String(length=32), nullable=False,
        server_default="scanner"))
    op.add_column("findings", sa.Column(
        "triage_status", sa.String(length=16), nullable=False,
        server_default="triaged"))
    op.add_column("findings", sa.Column(
        "evidence_level", sa.String(length=16), nullable=False,
        server_default="observed"))
    op.add_column("findings", sa.Column(
        "exploit_state", sa.String(length=16), nullable=False,
        server_default="none"))
    op.add_column("findings", sa.Column(
        "evidence_id", sa.String(length=36), nullable=True))
    op.create_foreign_key("fk_findings_evidence", "findings",
                          "finding_attachments", ["evidence_id"], ["id"])
    op.add_column("findings", sa.Column(
        "triaged_by", sa.String(length=255), nullable=True))
    op.add_column("findings", sa.Column(
        "triaged_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("triage_note", sa.Text(), nullable=True))

    op.create_index("ix_findings_origin", "findings", ["origin"])
    op.create_index("ix_findings_triage_status", "findings", ["triage_status"])

    # A finding no longer needs a project: an asset-only row is a real finding, and
    # the old NOT NULL forced a fake project instead.
    op.alter_column("findings", "project_id", existing_type=sa.String(length=36),
                    nullable=True)

    op.add_column("pentest_findings", sa.Column(
        "ingested_finding_id", sa.String(length=36), nullable=True))
    op.create_foreign_key("fk_pentest_findings_ingested", "pentest_findings",
                          "findings", ["ingested_finding_id"], ["id"])
    op.create_index("ix_pentest_findings_ingested", "pentest_findings",
                    ["ingested_finding_id"])


def downgrade() -> None:
    op.drop_index("ix_pentest_findings_ingested", table_name="pentest_findings")
    op.drop_constraint("fk_pentest_findings_ingested", "pentest_findings",
                       type_="foreignkey")
    op.drop_column("pentest_findings", "ingested_finding_id")

    # Rows without a project cannot survive the old constraint; give them one rather
    # than deleting evidence.
    op.execute("""
        UPDATE findings SET project_id = (
            SELECT id FROM projects WHERE projects.org_id = findings.org_id
            ORDER BY created_at LIMIT 1)
        WHERE project_id IS NULL
    """)
    op.alter_column("findings", "project_id", existing_type=sa.String(length=36),
                    nullable=False)

    op.drop_index("ix_findings_triage_status", table_name="findings")
    op.drop_index("ix_findings_origin", table_name="findings")
    op.drop_column("findings", "triage_note")
    op.drop_column("findings", "triaged_at")
    op.drop_column("findings", "triaged_by")
    op.drop_constraint("fk_findings_evidence", "findings", type_="foreignkey")
    op.drop_column("findings", "evidence_id")
    op.drop_column("findings", "exploit_state")
    op.drop_column("findings", "evidence_level")
    op.drop_column("findings", "triage_status")
    op.drop_column("findings", "origin")
    op.drop_index("ix_findings_asset_id", table_name="findings")
    op.drop_constraint("fk_findings_asset", "findings", type_="foreignkey")
    op.drop_column("findings", "asset_id")

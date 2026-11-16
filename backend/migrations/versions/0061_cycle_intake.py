"""cycle intake: a run declares its cycle, and its findings are claims

Two columns, and the rule they make possible:

  * `scan_jobs.cycle_id` — a tool is launched *into* a cycle. System jobs
    (advisory clock, coverage enrichment) leave it null, because they are not
    somebody's campaign.
  * `findings.origin_run_id` — a finding created from a run points at the run that
    claimed it, so the trace survives while the finding belongs to no asset yet.

The behaviour those columns enable lives in `routers/surface.py`: findings are
created for every target (no longer dropped when the asset carries no project),
with `triage_status='new'` and `asset_id` null, and linked to the declared cycle
through `cycle_findings`. Promotion to an asset is a human decision.

No backfill: the 577 existing findings keep their rows and their triage state. A
backfill of `origin_run_id` would have to guess which run produced each row, and a
guess written into evidence is worse than a null.

Revision ID: 0061_cycle_intake
Revises: 0060_kev_catalog
Create Date: 2026-11-09
"""

from alembic import op
import sqlalchemy as sa


revision = "0061_cycle_intake"
down_revision = "0060_kev_catalog"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scan_jobs", sa.Column(
        "cycle_id", sa.String(length=36), nullable=True))
    op.create_foreign_key("fk_scan_jobs_cycle", "scan_jobs", "cycles",
                          ["cycle_id"], ["id"])
    op.create_index("ix_scan_jobs_cycle_id", "scan_jobs", ["cycle_id"])

    op.add_column("findings", sa.Column(
        "origin_run_id", sa.String(length=36), nullable=True))
    op.create_foreign_key("fk_findings_origin_run", "findings", "scan_jobs",
                          ["origin_run_id"], ["id"])
    op.create_index("ix_findings_origin_run_id", "findings", ["origin_run_id"])


def downgrade() -> None:
    op.drop_index("ix_findings_origin_run_id", table_name="findings")
    op.drop_constraint("fk_findings_origin_run", "findings", type_="foreignkey")
    op.drop_column("findings", "origin_run_id")

    op.drop_index("ix_scan_jobs_cycle_id", table_name="scan_jobs")
    op.drop_constraint("fk_scan_jobs_cycle", "scan_jobs", type_="foreignkey")
    op.drop_column("scan_jobs", "cycle_id")

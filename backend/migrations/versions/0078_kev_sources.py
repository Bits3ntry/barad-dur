"""kev_sources: the mirror merges catalogues instead of mirroring one

`kev_entries` held CISA's catalog and nothing else, so "is this CVE known to be
exploited" answered with CISA's opinion — the EU list carries rows CISA never
added, and VulnCheck's is wider and often earlier. The row stays keyed on the CVE
because every other screen joins on it, so provenance has to be a column, not
three tables: `sources` lists the catalogues that say so, and the fields only the
EU list publishes (exploitation type, EUVD id, the report) get columns too.

`kev_feed_state` is the other half: one row per catalogue saying when it last
answered and what it said when it did not, because a merged row cannot tell a
fresh CISA sync from an EU feed that has been failing for a week.

The backfill is local and honest — every row that exists came from CISA, so that
is what `sources` says, and the CISA state row inherits the newest `fetched_at`
instead of claiming the catalogue was never synced.

Revision ID: 0078_kev_sources
Revises: 0077_org_members
Create Date: 2026-11-11
"""

from alembic import op
import sqlalchemy as sa


revision = "0078_kev_sources"
down_revision = "0077_org_members"
branch_labels = None
depends_on = None

COLUMNS = (
    ("sources", sa.String(length=255)),
    ("exploitation_type", sa.String(length=32)),
    ("euvd_id", sa.String(length=32)),
    ("notes", sa.Text()),
    ("eu_evidence", sa.Text()),
)


def upgrade() -> None:
    for name, kind in COLUMNS:
        op.add_column("kev_entries", sa.Column(name, kind, nullable=True))
    op.create_index("ix_kev_entries_sources", "kev_entries", ["sources"])

    op.create_table(
        "kev_feed_state",
        sa.Column("source", sa.String(32), primary_key=True),
        sa.Column("label", sa.String(64), nullable=True),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("last_ok_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_ok_rows", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("last_error_at", sa.DateTime(timezone=True), nullable=True),
    )

    bind = op.get_bind()
    bind.execute(sa.text(
        "UPDATE kev_entries SET sources = 'cisa-kev' WHERE sources IS NULL"))
    newest = bind.execute(sa.text("SELECT max(fetched_at) FROM kev_entries")).scalar()
    rows = bind.execute(sa.text("SELECT count(*) FROM kev_entries")).scalar() or 0
    if newest is not None:
        bind.execute(
            sa.text("INSERT INTO kev_feed_state (source, label, url, last_ok_at, "
                    "last_ok_rows) VALUES (:source, :label, :url, :last_ok_at, :rows)"),
            {"source": "cisa-kev", "label": "CISA KEV",
             "url": "https://www.cisa.gov/sites/default/files/feeds/"
                    "known_exploited_vulnerabilities.json",
             "last_ok_at": newest, "rows": rows})


def downgrade() -> None:
    op.drop_table("kev_feed_state")
    op.drop_index("ix_kev_entries_sources", table_name="kev_entries")
    for name, _kind in COLUMNS:
        op.drop_column("kev_entries", name)

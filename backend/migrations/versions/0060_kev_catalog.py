"""kev catalog: the feed carries vendor, product, name and description

The KEV table was reduced to `(cve_id, date_added, due_date)` on import and `title`
was read from a field the CISA feed does not have (`title`), so all 1769 rows came
back with `title: null`. That made the feed unusable for the question it exists to
answer — "what came out this week, and does it touch anything I run?" — because
there was nothing to search or to match a product against.

`upgrade` adds the columns the feed already carries. The data lands on the next
`POST /intel/sync`; a backfill inside the migration would need egress and is
deliberately not done here.

Revision ID: 0060_kev_catalog
Revises: 0059_mission_profile
Create Date: 2026-11-09
"""

from alembic import op
import sqlalchemy as sa


revision = "0060_kev_catalog"
down_revision = "0059_mission_profile"
branch_labels = None
depends_on = None

COLUMNS = (
    ("vendor", sa.String(length=255)),
    ("product", sa.String(length=255)),
    ("name", sa.Text()),
    ("description", sa.Text()),
    ("required_action", sa.Text()),
    ("ransomware", sa.String(length=32)),
    ("cwes", sa.String(length=255)),
)


def upgrade() -> None:
    for name, kind in COLUMNS:
        op.add_column("kev_entries", sa.Column(name, kind, nullable=True))
    op.create_index("ix_kev_entries_date_added", "kev_entries", ["date_added"])
    op.create_index("ix_kev_entries_product", "kev_entries", ["product"])


def downgrade() -> None:
    op.drop_index("ix_kev_entries_product", table_name="kev_entries")
    op.drop_index("ix_kev_entries_date_added", table_name="kev_entries")
    for name, _kind in COLUMNS:
        op.drop_column("kev_entries", name)

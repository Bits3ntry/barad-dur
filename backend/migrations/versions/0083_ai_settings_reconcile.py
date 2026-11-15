"""reconcile the AI ceilings a row kept from an older default

`engine.settings_row()` creates the row with the model's defaults, so a NULL
`updated_by` means no human ever changed it: the numbers are whatever the default was
on the day the row was born. Two of them stopped being able to complete the documented
chain — 6 steps and 3 specialists against a five-specialist plan — and every CVE
question ended `stopped_max_steps` with facts and no answer.

This is not the first time: `max_steps` went 6 → 12 when the investigation chain needed
the room, and the live row kept 6. Reconciling here is the fix for the class, not for
the row.

Only untouched rows are updated: a ceiling a person set is a decision, and a migration
that overrides one is worse than a stale default.

Revision ID: 0083_ai_settings_reconcile
Revises: 0082_graph_edge_id_width
"""

from alembic import op

revision = "0083_ai_settings_reconcile"
down_revision = "0082_graph_edge_id_width"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("UPDATE ai_settings SET max_steps = 12 "
               "WHERE updated_by IS NULL AND max_steps < 12")
    op.execute("UPDATE ai_settings SET max_specialists = 6 "
               "WHERE updated_by IS NULL AND max_specialists < 6")


def downgrade() -> None:
    # Nothing to undo: the values replaced were defaults nobody chose. Restoring them
    # would put an unanswerable ceiling back on a running estate.
    pass

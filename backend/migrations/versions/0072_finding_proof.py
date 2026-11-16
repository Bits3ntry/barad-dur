"""finding proof: the fingerprint of what happened, where and how

A hand-written vulnerability used to be a title and a url. A pentest report is not
that: it names the weakness class, the product, the exact endpoint and method, the
authentication needed to reach it, the raw request that proves it, what we expected
and what actually came back. Those are the fields that make a finding reproducible.

`auth_profiles` holds reusable session recipes (bearer, cookie, header, form login):
a login is not part of one finding, it is how the tester gets in — the same recipe is
used by every finding of the engagement.

Revision ID: 0072_finding_proof
Revises: 0071_cycle_documents
"""

from alembic import op
import sqlalchemy as sa

revision = "0072_finding_proof"
down_revision = "0071_cycle_documents"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "auth_profiles",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False, server_default="bearer"),
        sa.Column("headers", sa.Text(), nullable=True),
        sa.Column("login_steps", sa.Text(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.UniqueConstraint("org_id", "name", name="uq_auth_profiles_org_name"),
    )
    op.create_index("ix_auth_profiles_org", "auth_profiles", ["org_id"])

    op.add_column("findings", sa.Column("http_method", sa.String(16), nullable=True))
    op.add_column("findings", sa.Column("endpoint", sa.String(2048), nullable=True))
    op.add_column("findings", sa.Column("auth_required", sa.Boolean(), nullable=True))
    op.add_column("findings", sa.Column("auth_profile_id", sa.String(36),
                                        sa.ForeignKey("auth_profiles.id"), nullable=True))
    op.add_column("findings", sa.Column("expected_result", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("observed_result", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("validation_output", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("proof_request", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("proof_response", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("product_component_id", sa.String(36),
                                        sa.ForeignKey("application_components.id"),
                                        nullable=True))


def downgrade() -> None:
    for column in ("product_component_id", "proof_response", "proof_request",
                   "validation_output", "observed_result", "expected_result",
                   "auth_profile_id", "auth_required", "endpoint", "http_method"):
        op.drop_column("findings", column)
    op.drop_index("ix_auth_profiles_org", table_name="auth_profiles")
    op.drop_table("auth_profiles")

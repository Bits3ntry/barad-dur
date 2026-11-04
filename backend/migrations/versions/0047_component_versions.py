"""Migration 0047: a version belongs to a component.

The hierarchy the inventory promises is Project → Component → Code → Environment
→ Assets. `project_versions` was scoped to the project, so the SBOM of the
backend and the SBOM of the web competed for the same row; deployments matched
their version by string, so renaming one orphaned the other.

- `project_versions.component_id` (nullable) scopes a version to a component.
  NULL stays meaningful: a product-wide release, when several components ship as
  one train.
- `deployments.version_id` replaces the string match. `version_label` stays as
  the display mirror the probe writes to.

Backfill is deliberate: a project version with no component adopts the component
of the single deployment that already declares it, so an SBOM uploaded before
this migration keeps its link instead of landing in an empty twin.
"""
from alembic import op
import sqlalchemy as sa

revision = "0047_component_versions"
down_revision = "0046_project_profile"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("project_versions",
                  sa.Column("component_id", sa.String(36), nullable=True))
    # The model has carried TimestampMixin since 0001 but the table never got the
    # column: any insert through SQLAlchemy failed on Postgres.
    existing = {column["name"] for column in
                sa.inspect(op.get_bind()).get_columns("project_versions")}
    if "updated_at" not in existing:
        op.add_column("project_versions",
                      sa.Column("updated_at", sa.DateTime(timezone=True),
                                server_default=sa.func.now(), nullable=False))
    op.create_index("ix_project_versions_component_id", "project_versions",
                    ["component_id"])
    with op.batch_alter_table("project_versions") as batch:
        batch.drop_constraint("uq_project_versions_pair", type_="unique")
    op.create_index("uq_project_version_scope", "project_versions",
                    ["project_id", "component_id", "version"], unique=True)
    # Postgres and SQLite both allow many NULLs in a unique index, so the
    # product-wide rows need their own partial one.
    op.create_index("uq_project_version_product", "project_versions",
                    ["project_id", "version"], unique=True,
                    postgresql_where=sa.text("component_id IS NULL"),
                    sqlite_where=sa.text("component_id IS NULL"))
    op.add_column("deployments", sa.Column("version_id", sa.String(36), nullable=True))
    op.create_index("ix_deployments_version_id", "deployments", ["version_id"])

    connection = op.get_bind()
    rows = connection.execute(sa.text("""
        SELECT d.id, d.version_label, c.project_id, d.application_component_id
        FROM deployments d
        JOIN application_components c ON c.id = d.application_component_id
        WHERE d.version_label IS NOT NULL AND d.version_label <> ''
    """)).fetchall()

    # 1. A project-wide version with exactly one declaring deployment adopts that
    #    component: the SBOM already attached to it is that component's SBOM.
    for deployment_id, label, project_id, component_id in rows:
        connection.execute(sa.text("""
            UPDATE project_versions SET component_id = :component
            WHERE project_id = :project AND version = :version
              AND component_id IS NULL
              AND (SELECT COUNT(*) FROM deployments d2
                   JOIN application_components c2 ON c2.id = d2.application_component_id
                   WHERE c2.project_id = :project AND d2.version_label = :version) = 1
        """), {"component": component_id, "project": project_id, "version": label})

    # 2. Every deployment gets the component-scoped version it declares.
    for deployment_id, label, project_id, component_id in rows:
        existing = connection.execute(sa.text("""
            SELECT id FROM project_versions
            WHERE project_id = :project AND version = :version
              AND component_id = :component
        """), {"project": project_id, "version": label, "component": component_id}).fetchone()
        if existing is None:
            existing = connection.execute(sa.text("""
                INSERT INTO project_versions (id, project_id, component_id, version,
                                              created_at)
                VALUES (:id, :project, :component, :version, CURRENT_TIMESTAMP)
                RETURNING id
            """), {"id": _uuid(), "project": project_id, "component": component_id,
                   "version": label}).fetchone()
        connection.execute(sa.text("UPDATE deployments SET version_id = :vid WHERE id = :did"),
                           {"vid": existing[0], "did": deployment_id})


def downgrade() -> None:
    op.drop_index("ix_deployments_version_id", table_name="deployments")
    with op.batch_alter_table("deployments") as batch:
        batch.drop_column("version_id")
    op.drop_index("uq_project_version_product", table_name="project_versions")
    op.drop_index("uq_project_version_scope", table_name="project_versions")
    # Collapse component-scoped rows onto their product-wide label before the old
    # uniqueness comes back; the oldest row per (project, version) wins.
    connection = op.get_bind()
    connection.execute(sa.text("""
        DELETE FROM project_versions pv
        WHERE pv.component_id IS NOT NULL
          AND EXISTS (SELECT 1 FROM project_versions other
                      WHERE other.project_id = pv.project_id
                        AND other.version = pv.version AND other.id <> pv.id
                        AND other.created_at <= pv.created_at)
    """))
    connection.execute(sa.text(
        "UPDATE project_versions SET component_id = NULL WHERE component_id IS NOT NULL"))
    with op.batch_alter_table("project_versions") as batch:
        batch.create_unique_constraint("uq_project_versions_pair",
                                       ["project_id", "version"])
    op.drop_index("ix_project_versions_component_id", table_name="project_versions")
    with op.batch_alter_table("project_versions") as batch:
        batch.drop_column("component_id")
        batch.drop_column("updated_at")


def _uuid() -> str:
    import uuid
    return uuid.uuid4().hex

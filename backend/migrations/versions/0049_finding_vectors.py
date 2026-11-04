"""Give every finding a vector, and separate secrets from code defects.

`kind` answers "what kind of thing is this" (three classes). It does not answer
"how is it closed", and that is what the console needs: a CVE is closed by
upgrading a package, a credential by rotating it, a code defect by changing the
code. This migration adds the missing axis and reclassifies what already exists.

Existing rows are corrected, not duplicated: a secret found by gitleaks becomes
`kind=vulnerability, vector=credential`, which changes its recipe fingerprint —
so the fingerprint is recomputed here for exactly those rows, in Python, because
the recipe lives in code and must not be re-implemented in SQL.
"""
import hashlib

import sqlalchemy as sa
from alembic import op

revision = "0049_finding_vectors"
down_revision = "0048_scan_flows"
branch_labels = None
depends_on = None


def _recipe(kind: str, org_id: str, project_id: str, rule_id, path) -> str:
    """Mirror of incidents.recipe_fingerprint; frozen here on purpose."""
    base = f"v1|{kind}|{org_id}|{project_id}|{rule_id}|{path}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


def upgrade() -> None:
    op.add_column("findings", sa.Column("vector", sa.String(length=32), nullable=True))
    op.create_index("ix_findings_vector", "findings", ["vector"])

    # The receipt now counts advisories, not just components.
    for column in ("vulnerabilities_received", "vulnerabilities_created",
                   "vulnerabilities_refreshed", "vulnerabilities_unresolved"):
        op.add_column("sbom_imports",
                      sa.Column(column, sa.Integer(), nullable=False, server_default="0"))

    bind = op.get_bind()

    # A secret is a vulnerability: it is exploitable now, and it is closed by a
    # rotation rather than a commit.
    secrets = bind.execute(sa.text(
        "SELECT id, org_id, project_id, rule_id, path FROM findings "
        "WHERE kind = 'code-weakness' AND (tool ILIKE '%gitleaks%' OR tool ILIKE '%secret%')"
    )).fetchall()
    for row in secrets:
        fingerprint = _recipe("vulnerability", row.org_id, row.project_id,
                              row.rule_id, row.path)
        bind.execute(sa.text(
            "UPDATE findings SET kind = 'vulnerability', vector = 'credential', "
            "severity = 'CRITICAL', fingerprint = :fp, updated_at = now() WHERE id = :id"
        ), {"fp": fingerprint, "id": row.id})

    # Everything Trivy found outside secret scanning is a configuration defect.
    bind.execute(sa.text(
        "UPDATE findings SET vector = 'misconfig', updated_at = now() "
        "WHERE vector IS NULL AND kind = 'code-weakness' AND tool ILIKE '%trivy%'"
    ))
    # The rest of code-weakness is source analysis.
    bind.execute(sa.text(
        "UPDATE findings SET vector = 'sast', updated_at = now() "
        "WHERE vector IS NULL AND kind = 'code-weakness'"
    ))
    # Vulnerabilities already in the table came from the OSV engine.
    bind.execute(sa.text(
        "UPDATE findings SET vector = 'dependency-cve', updated_at = now() "
        "WHERE vector IS NULL AND kind = 'vulnerability'"
    ))


def downgrade() -> None:
    bind = op.get_bind()
    # Put secrets back where they were so downgrade is symmetric (best effort:
    # the fingerprints computed above are re-derived by the same recipe).
    rows = bind.execute(sa.text(
        "SELECT id, org_id, project_id, rule_id, path FROM findings "
        "WHERE kind = 'vulnerability' AND vector = 'credential'"
    )).fetchall()
    for row in rows:
        fingerprint = _recipe("code-weakness", row.org_id, row.project_id,
                              row.rule_id, row.path)
        bind.execute(sa.text(
            "UPDATE findings SET kind = 'code-weakness', vector = NULL, "
            "fingerprint = :fp WHERE id = :id"
        ), {"fp": fingerprint, "id": row.id})
    bind.execute(sa.text("UPDATE findings SET vector = NULL"))
    for column in ("vulnerabilities_received", "vulnerabilities_created",
                   "vulnerabilities_refreshed", "vulnerabilities_unresolved"):
        op.drop_column("sbom_imports", column)
    op.drop_index("ix_findings_vector", table_name="findings")
    op.drop_column("findings", "vector")

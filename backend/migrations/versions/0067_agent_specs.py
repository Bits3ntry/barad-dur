"""agents: the catalogue the thread is built on

Four rows and two tables, no behaviour: an agent is a *declaration* (name, avatar,
class, the tools it may use, the contract it must return) and the thread is an
append-only event log. The first phase ships the catalogue and the thread; the field
tools land next, which is why `validate.finding` is seeded as `draft` — it declares
tools that do not exist yet, and the console says so instead of pretending.

Deployment-wide on purpose, like `ai_providers`: the harness is one per deployment and
the operators are the same people. `agent_events` carries `org_id` because a thread
belongs to one estate's question.

Revision ID: 0067_agent_specs
Revises: 0066_threat_model
Create Date: 2026-11-09
"""

from alembic import op
import sqlalchemy as sa


revision = "0067_agent_specs"
down_revision = "0066_threat_model"
branch_labels = None
depends_on = None

#: name, slug, class, description, avatar, color, tools, must_return, status
SEED = [
    ("Palantír", "palantir", "orchestrator",
     "The seeing stone: plans, cites and never executes. Opens with the plan and "
     "waits for the operator before anything touchable happens.",
     "🔮", "#a855f7", "[]",
     '["answer", "citations", "open_questions"]', "active"),
    ("Analyst", "estate.analyst", "analyst",
     "Reads inventory, versions, deployments and findings. Every number comes from "
     "a row and carries its id.",
     "🗂️", "#38bdf8",
     '["projects_list", "project_inventory", "components_impact", "deployment_chain", '
     '"vulnerabilities_search", "findings_search", "assets_search", '
     '"advisory_resolve", "intel_kev_catalog"]',
     '["answer", "citations"]', "active"),
    ("Change impact", "change.impact", "analyst",
     "What an upgrade closes, what it breaks, and in which order. Reads diffs, "
     "dependents, findings and deployments; touches no target.",
     "🔁", "#f59e0b",
     '["compare_versions", "components_impact", "vulnerabilities_search", '
     '"findings_search", "deployment_chain"]',
     '["closes", "breaks", "order", "citations"]', "active"),
    ("Validator", "validate.finding", "field",
     "Reproduces a finding that already exists: the stored request, the same target, "
     "one artefact. No crawling, no payloads, no login.",
     "🎯", "#22c55e",
     '["findings_search", "deployment_chain"]',
     '["state", "request", "response", "diff", "artifact"]', "draft"),
]


def upgrade() -> None:
    op.create_table(
        "agent_specs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("slug", sa.String(64), nullable=False, unique=True),
        sa.Column("agent_class", sa.String(24), nullable=False,
                  server_default="analyst"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("avatar", sa.String(8), nullable=True),
        sa.Column("color", sa.String(16), nullable=True),
        sa.Column("tools", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("must_return", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("tech_affinity", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("status", sa.String(16), nullable=False, server_default="draft"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_agent_specs_status", "agent_specs", ["status"])

    op.create_table(
        "agent_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id"),
                  nullable=False),
        sa.Column("thread", sa.String(80), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("author_spec", sa.String(64), nullable=True),
        sa.Column("actor", sa.String(255), nullable=True),
        sa.Column("kind", sa.String(24), nullable=False,
                  server_default="message"),
        sa.Column("body", sa.Text(), nullable=True),
        sa.Column("refs", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_agent_events_thread_seq", "agent_events", ["thread", "seq"])
    op.create_index("ix_agent_events_org", "agent_events", ["org_id"])

    table = sa.table(
        "agent_specs",
        sa.column("id", sa.String),
        sa.column("name", sa.String),
        sa.column("slug", sa.String),
        sa.column("agent_class", sa.String),
        sa.column("description", sa.Text),
        sa.column("avatar", sa.String),
        sa.column("color", sa.String),
        sa.column("tools", sa.Text),
        sa.column("must_return", sa.Text),
        sa.column("status", sa.String),
    )
    for index, row in enumerate(SEED):
        name, slug, klass, description, avatar, color, tools, must_return, status = row
        op.execute(table.insert().values(
            id=f"spec-{slug}", name=name, slug=slug, agent_class=klass,
            description=description, avatar=avatar, color=color, tools=tools,
            must_return=must_return, status=status))


def downgrade() -> None:
    op.drop_index("ix_agent_events_org", table_name="agent_events")
    op.drop_index("ix_agent_events_thread_seq", table_name="agent_events")
    op.drop_table("agent_events")
    op.drop_index("ix_agent_specs_status", table_name="agent_specs")
    op.drop_table("agent_specs")

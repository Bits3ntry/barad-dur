"""threat model: techniques per crown jewel, and the profiles that choose them

Three tables, one idea: a jewel does not get "a scan", it gets the techniques an
attacker would actually use against it, each mapped to the MITRE ATT&CK technique
that names it and to the platform capability that could test it.

  attack_techniques  the reference catalogue (ATT&CK id, tactic, capability)
  threat_entries     (jewel, technique, why) — the model of one crown jewel
  attacker_profiles  reusable bundles of techniques, org-scoped

`capability = NULL` is the honest case: a technique we cannot test with anything we
run today (phishing, DoS, exfiltration). It is listed, counted, and never scored as
covered — a technique nobody can test is not a gap in our tooling, it is a fact
about the platform's reach.

Revision ID: 0066_threat_model
Revises: 0065_component_crown_jewels
Create Date: 2026-11-09
"""

from alembic import op
import sqlalchemy as sa


revision = "0066_threat_model"
down_revision = "0065_component_crown_jewels"
branch_labels = None
depends_on = None


CATALOG = [
    # (id, name, tactic, capability, description)
    ("T1595", "Active Scanning", "Reconnaissance", "active_verification",
     "Probing for open services and exploitable surface"),
    ("T1592", "Gather Victim Host Information", "Reconnaissance", "passive_discovery",
     "Fingerprinting hosts, versions and technologies"),
    ("T1590", "Gather Victim Network Information", "Reconnaissance", "passive_discovery",
     "DNS, certificates and address space"),
    ("T1593", "Search Open Websites/Domains", "Reconnaissance", "passive_discovery",
     "Public sources that describe or expose the target"),
    ("T1596", "Search Open Technical Databases", "Reconnaissance", "passive_discovery",
     "Certificate transparency, registries, leaked datasets"),
    ("T1598", "Phishing for Information", "Reconnaissance", None,
     "Social engineering; not testable by this platform"),
    ("T1566", "Phishing", "Initial Access", None,
     "Social engineering; not testable by this platform"),
    ("T1190", "Exploit Public-Facing Application", "Initial Access", "intrusive_testing",
     "Template and exploit checks against an authorized service"),
    ("T1133", "External Remote Services", "Initial Access", "active_verification",
     "VPN, RDP, admin panels reachable from the internet"),
    ("T1078", "Valid Accounts", "Initial Access", "intrusive_testing",
     "Default or weak credentials on an exposed service"),
    ("T1110", "Brute Force", "Credential Access", "intrusive_testing",
     "Password guessing against an authorized login"),
    ("T1195", "Supply Chain Compromise", "Initial Access", "code_analysis",
     "Dependencies and build inputs of the product"),
    ("T1195.001", "Compromise Software Dependencies and Development Tools",
     "Initial Access", "code_analysis",
     "Malicious or hijacked dependency, registry or plugin"),
    ("T1195.002", "Compromise Software Supply Chain", "Initial Access", "code_analysis",
     "Build and release path of the product"),
    ("T1552", "Unsecured Credentials", "Credential Access", "code_analysis",
     "Secrets committed in code or build artefacts"),
    ("T1552.001", "Credentials In Files", "Credential Access", "code_analysis",
     "Keys and tokens present in repository files"),
    ("T1505.003", "Web Shell", "Persistence", "active_verification",
     "Upload and remote execution on a web server"),
    ("T1046", "Network Service Discovery", "Discovery", "active_verification",
     "Ports and services on the reachable address"),
    ("T1018", "Remote System Discovery", "Discovery", "passive_discovery",
     "Neighbouring hosts and subdomains"),
    ("T1199", "Trusted Relationship", "Initial Access", None,
     "Third-party trust; out of reach for this platform"),
    ("T1550.001", "Application Access Token", "Defense Evasion", None,
     "Token theft and replay; out of reach for this platform"),
    ("T1071", "Application Layer Protocol", "Command and Control", None,
     "C2 over web protocols; out of reach for this platform"),
    ("T1567", "Exfiltration Over Web Service", "Exfiltration", None,
     "Data leaving through a web service; out of reach for this platform"),
    ("T1499", "Endpoint Denial of Service", "Impact", None,
     "Availability testing is out of scope by policy"),
]


def upgrade() -> None:
    op.create_table(
        "attack_techniques",
        sa.Column("id", sa.String(length=24), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("tactic", sa.String(length=64), nullable=False),
        sa.Column("capability", sa.String(length=32), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
    )
    op.create_index("ix_attack_techniques_tactic", "attack_techniques", ["tactic"])

    op.create_table(
        "threat_entries",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("org_id", sa.String(length=36), sa.ForeignKey("organizations.id"),
                  nullable=False),
        sa.Column("component_id", sa.String(length=36),
                  sa.ForeignKey("application_components.id"), nullable=False),
        sa.Column("technique_id", sa.String(length=24),
                  sa.ForeignKey("attack_techniques.id"), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("added_by", sa.String(length=255), nullable=True),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("component_id", "technique_id",
                            name="uq_threat_entry_component_technique"),
    )
    op.create_index("ix_threat_entries_component", "threat_entries", ["component_id"])
    op.create_index("ix_threat_entries_org", "threat_entries", ["org_id"])

    op.create_table(
        "attacker_profiles",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("org_id", sa.String(length=36), sa.ForeignKey("organizations.id"),
                  nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("techniques", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("org_id", "name", name="uq_attacker_profile_name"),
    )

    table = sa.table("attack_techniques",
                     sa.column("id", sa.String), sa.column("name", sa.String),
                     sa.column("tactic", sa.String), sa.column("capability", sa.String),
                     sa.column("description", sa.Text))
    op.bulk_insert(table, [
        {"id": tid, "name": name, "tactic": tactic,
         "capability": capability, "description": description}
        for tid, name, tactic, capability, description in CATALOG
    ])


def downgrade() -> None:
    op.drop_table("attacker_profiles")
    op.drop_index("ix_threat_entries_org", table_name="threat_entries")
    op.drop_index("ix_threat_entries_component", table_name="threat_entries")
    op.drop_table("threat_entries")
    op.drop_index("ix_attack_techniques_tactic", table_name="attack_techniques")
    op.drop_table("attack_techniques")

"""F0 platform schema: organizations, keys, projects, versions, SBOM imports, components.

Types stay portable (string pk/ids, plain DateTime) so unit tests can run on
SQLite while the production deployment uses the Compose PostgreSQL
server. Organizations exist in the schema from day one; the POC API exposes
exactly one.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def uuid_hex() -> str:
    return uuid.uuid4().hex


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Organization(Base, TimestampMixin):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    slug: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(255))


class ApiKey(Base, TimestampMixin):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    label: Mapped[str] = mapped_column(String(255), default="")

    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Project(Base, TimestampMixin):
    __tablename__ = "projects"
    __table_args__ = (UniqueConstraint("org_id", "slug", name="uq_projects_org_slug"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    name: Mapped[str] = mapped_column(String(255))
    slug: Mapped[str] = mapped_column(String(255))


class ProjectVersion(Base, TimestampMixin):
    __tablename__ = "project_versions"
    __table_args__ = (
        UniqueConstraint("project_id", "version", name="uq_project_versions_pair"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"))
    version: Mapped[str] = mapped_column(String(255))


class SbomImport(Base, TimestampMixin):
    __tablename__ = "sbom_imports"
    __table_args__ = (
        UniqueConstraint("project_version_id", "content_sha256", name="uq_sbom_import_idempotent"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    project_version_id: Mapped[str] = mapped_column(String(36), ForeignKey("project_versions.id"))
    content_sha256: Mapped[str] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(32), default="api")
    filename: Mapped[str | None] = mapped_column(String(512), nullable=True)

    components_received: Mapped[int] = mapped_column(Integer, default=0)
    components_created: Mapped[int] = mapped_column(Integer, default=0)
    components_updated: Mapped[int] = mapped_column(Integer, default=0)
    components_skipped: Mapped[int] = mapped_column(Integer, default=0)
    links_created: Mapped[int] = mapped_column(Integer, default=0)


class Component(Base, TimestampMixin):
    __tablename__ = "components"
    __table_args__ = (UniqueConstraint("org_id", "identity_key", name="uq_components_org_identity"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    identity_key: Mapped[str] = mapped_column(String(1100), index=True)
    purl: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    bom_ref: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    license: Mapped[str | None] = mapped_column(String(512), nullable=True)
    manifest_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class VersionComponent(Base, TimestampMixin):
    __tablename__ = "version_components"
    __table_args__ = (
        UniqueConstraint("project_version_id", "component_id", name="uq_version_components_pair"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    project_version_id: Mapped[str] = mapped_column(String(36), ForeignKey("project_versions.id"))
    component_id: Mapped[str] = mapped_column(String(36), ForeignKey("components.id"))
    is_direct: Mapped[bool] = mapped_column(Boolean, default=False)
    parent_purl: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    manifest_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)


class Vulnerability(Base, TimestampMixin):
    """Global advisory catalog entry (no org scope), keyed by source id."""

    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    source_id: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    source: Mapped[str] = mapped_column(String(32), default="osv")
    cve_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    title: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(255), nullable=True)
    url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    published: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    modified: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Finding(Base, TimestampMixin):
    """One weakness/failure-of-one-component, deduped by fingerprint recipe.

    The fingerprint hashes the identity recipe (kind + org + project + the
    component identity + the advisory id for vulnerability kind), mirroring the
    reference platform's per-kind strategies; statuses (suppress/approve)
    arrive with F2.
    """

    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("org_id", "fingerprint", name="uq_findings_org_fingerprint"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"))
    kind: Mapped[str] = mapped_column(String(32), index=True)
    fingerprint: Mapped[str] = mapped_column(String(128), index=True)
    source: Mapped[str] = mapped_column(String(32))
    title: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    detail: Mapped[str] = mapped_column(Text, nullable=True)
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    component_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("components.id"), nullable=True)
    vulnerability_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("vulnerabilities.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="open")
    status_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    status_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    priority: Mapped[str | None] = mapped_column(String(8), nullable=True, index=True)
    priority_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    sla_deadline: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Scan context: multi-kind findings carry no component row, so the version
    # they were last seen in is stamped here (also used by list filters).
    last_seen_version_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("project_versions.id"), nullable=True, index=True)
    tool: Mapped[str | None] = mapped_column(String(32), nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SuppressionRule(Base, TimestampMixin):
    """Tenant-level rule keyed on finding attributes, with an embedded
    approval workflow: a requester can never approve their own rule."""
    __tablename__ = "suppression_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    project_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("projects.id"), nullable=True)
    kind: Mapped[str | None] = mapped_column(String(32), nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    path_pattern: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    suppression_type: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    requested_by: Mapped[str] = mapped_column(String(255))
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FindingSuppression(Base, TimestampMixin):
    """Per-finding application row of an approved suppression rule."""

    __tablename__ = "finding_suppressions"
    __table_args__ = (
        UniqueConstraint("finding_id", "rule_id", name="uq_finding_suppression_pair"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id"))
    rule_id: Mapped[str] = mapped_column(String(36), ForeignKey("suppression_rules.id"))
    applied_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    applied_by: Mapped[str | None] = mapped_column(String(255), nullable=True)


class PriorityRule(Base, TimestampMixin):
    """Ordered classification rule: first match wins (their priority_rules
    recipe, slimmed to attribute matches; scoring explanations stay honest)."""

    __tablename__ = "priority_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    position: Mapped[int] = mapped_column(Integer, default=0)
    match_kind: Mapped[str | None] = mapped_column(String(32), nullable=True)
    match_severities: Mapped[str | None] = mapped_column(String(255), nullable=True)
    match_source: Mapped[str | None] = mapped_column(String(32), nullable=True)
    priority: Mapped[str] = mapped_column(String(8))
    reason: Mapped[str] = mapped_column(Text)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SlaPolicy(Base, TimestampMixin):
    """Day buckets per priority class; one default policy per org."""

    __tablename__ = "sla_policies"
    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_sla_policies_org_name"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    name: Mapped[str] = mapped_column(String(255))
    p0_days: Mapped[int] = mapped_column(Integer)
    p1_days: Mapped[int] = mapped_column(Integer)
    p2_days: Mapped[int] = mapped_column(Integer)
    p3_days: Mapped[int] = mapped_column(Integer)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RemediationTask(Base, TimestampMixin):
    """A unit of fix work carrying one or more findings (their
    remediation_tasks: a finding belongs to at most one open task)."""

    __tablename__ = "remediation_tasks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    title: Mapped[str] = mapped_column(String(512))
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RemediationFinding(Base):
    """Task membership row; removed_at marks detach (audit without deleting).
    Deliberately no TimestampMixin: added_at is the timestamp of record (the
    migration ships only added_at/removed_at)."""

    __tablename__ = "remediation_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    task_id: Mapped[str] = mapped_column(String(36), ForeignKey("remediation_tasks.id"))
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id"))
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


ROLES = {"owner", "admin", "analyst", "viewer"}


class OrgMember(Base, TimestampMixin):
    """The POC identity surface: named members with a role. Authentication is
    still the org's API key (ODIC/password flows are the post-POC backlog),
    but membership carries the accountability side (added_by, role)."""

    __tablename__ = "org_members"
    __table_args__ = (
        UniqueConstraint("org_id", "identity", name="uq_org_members_identity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    identity: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="viewer")
    added_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="active")

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    """Append-only per-org ledger with a tamper-evident chain: each entry
    commits `hash = sha256(prev_hash | position | payload)`; the appender
    chain rides a transaction so two writers can never fork the tail."""

    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    actor: Mapped[str] = mapped_column(String(255), default="system")
    action: Mapped[str] = mapped_column(String(255))
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    chain_position: Mapped[int] = mapped_column(Integer)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class KevEntry(Base):
    """One CISA KEV row mirrored locally (catalog lives at cisa.gov)."""

    __tablename__ = "kev_entries"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    date_added: Mapped[str | None] = mapped_column(String(32), nullable=True)
    due_date: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source: Mapped[str | None] = mapped_column(String(255), nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EpssScore(Base):
    """One FIRST EPSS row mirrored locally (probability 0..1 + percentile)."""

    __tablename__ = "epss_scores"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    epss: Mapped[str] = mapped_column(String(16))
    percentile: Mapped[str | None] = mapped_column(String(16), nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class VexStatement(Base, TimestampMixin):
    """Our own VEX statement column for one finding (their vex_conclusions
    concept, POC-slimmed: statement + status, no machine-signed docs yet)."""

    __tablename__ = "vex_statements"
    __table_args__ = (
        Index("ix_vex_finding", "finding_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id"))
    status: Mapped[str] = mapped_column(String(32))
    statement: Mapped[str] = mapped_column(Text)
    author: Mapped[str | None] = mapped_column(String(255), nullable=True)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


ASSET_TYPES = {"domain", "ip", "url", "cidr"}


class Asset(Base):
    """One externally observable asset (their EASM inventory, POC-slimmed:
    domains via certificate transparency, everything else manual for now)."""

    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("org_id", "type", "value", name="uq_assets_triple"),
        Index("ix_assets_type", "type"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    type: Mapped[str] = mapped_column(String(32))
    value: Mapped[str] = mapped_column(String(1024))
    source: Mapped[str] = mapped_column(String(64))
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CiPipeline(Base, TimestampMixin):
    """One customer CI pipeline that reports to the platform (their ci_pipelines
    concept, slimmed: identity + metadata, no OIDC trust in the POC)."""

    __tablename__ = "ci_pipelines"
    __table_args__ = (
        UniqueConstraint("org_id", "provider", "repository", "workflow_path",
                         name="uq_ci_pipelines_identity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    provider: Mapped[str] = mapped_column(String(32), default="github")
    repository: Mapped[str] = mapped_column(String(512))
    workflow_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CiRun(Base, TimestampMixin):
    """One CI pipeline execution that reported findings. The verdict is
    computed fail-closed from the run's severity histogram; reason strings
    are capped because the verdict renders in public CI logs."""

    __tablename__ = "ci_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    pipeline_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("ci_pipelines.id"), nullable=True)
    ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event: Mapped[str | None] = mapped_column(String(64), nullable=True)
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="running")
    verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    verdict_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CiRunFinding(Base, TimestampMixin):
    """Run-to-finding attachment (their ci_run_findings bridge, simplified to
    an id FK in the POC; the fingerprint bridge matters only under merging)."""

    __tablename__ = "ci_run_findings"
    __table_args__ = (
        UniqueConstraint("run_id", "finding_id", name="uq_ci_run_findings_pair"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    run_id: Mapped[str] = mapped_column(String(36), ForeignKey("ci_runs.id"))
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id"))
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)


class ScopeTarget(Base, TimestampMixin):
    """What the organization may audit or analyze: static positive list."""


    __tablename__ = "scope_targets"
    __table_args__ = (
        UniqueConstraint("org_id", "target_type", "value", name="uq_scope_targets_identity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    target_type: Mapped[str] = mapped_column(String(32))
    value: Mapped[str] = mapped_column(String(1024))
    status: Mapped[str] = mapped_column(String(32), default="active")
    note: Mapped[str | None] = mapped_column(Text, nullable=True)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ScopeExclusion(Base, TimestampMixin):
    """Negative scope entries; resolved view subtracts these from targets."""

    __tablename__ = "scope_exclusions"
    __table_args__ = (
        UniqueConstraint("org_id", "target_type", "value", name="uq_scope_exclusions_identity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    target_type: Mapped[str] = mapped_column(String(32))
    value: Mapped[str] = mapped_column(String(1024))
    reason: Mapped[str] = mapped_column(Text)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ─────────────── BL-010: typed, temporal, auditable relationships ───────────────

LINK_ENTITY_TYPES = {"project", "service", "deployment", "repository", "asset"}
CONTEXT_ENTITY_TYPES = {"repository", "service", "deployment", "asset"}
LINK_RELATIONS = {
    "project": {"serves", "uses", "monitors"},
    "service": {"serves", "uses", "monitors"},
    "deployment": {"exposes", "is_deployed_at", "observed_at"},
    "repository": {"observed_in"},
    "asset": {"observed_in"},
}


class Repository(Base):
    """One git remote — first-class entity, reusable across projects.
    Explicit created_at instead of TimestampMixin: the migration ships only
    that column (BL-010 teaches: never let padding drift a migration)."""

    __tablename__ = "repositories"
    __table_args__ = (
        UniqueConstraint("org_id", "remote_url", name="uq_repositories_remote"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    provider: Mapped[str] = mapped_column(String(32), default="git")
    name: Mapped[str] = mapped_column(String(255))
    remote_url: Mapped[str] = mapped_column(String(2048))
    last_commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ProjectRepository(Base):
    """Project ↔ repository N:M (temporal): removed links are history."""

    __tablename__ = "project_repositories"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36))
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), index=True)
    repository_id: Mapped[str] = mapped_column(String(36), ForeignKey("repositories.id"))
    relation: Mapped[str] = mapped_column(String(32), default="builds")
    added_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Service(Base):
    """A deployable/observable unit distinct from its projects and deployments
    (explicit created_at, no mixin — see Repository)."""

    __tablename__ = "services"
    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_services_org_name"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    name: Mapped[str] = mapped_column(String(255))
    runtime: Mapped[str | None] = mapped_column(String(64), nullable=True)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ServiceProject(Base):
    """Service ↔ project N:M (temporal)."""

    __tablename__ = "service_projects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36))
    service_id: Mapped[str] = mapped_column(String(36), ForeignKey("services.id"), index=True)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), index=True)
    relation: Mapped[str] = mapped_column(String(32), default="exposes")
    added_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Deployment(Base, TimestampMixin):
    """One environment-specific deployment of (usually) a service; domains
    ride the asset_links table, never a copy of the asset."""

    __tablename__ = "deployments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    service_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("services.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(255))
    environment: Mapped[str] = mapped_column(String(64), default="production")

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AssetLink(Base):
    """Typed, temporal asset attachment: asset ↔ (project | service |
    deployment). One row per pairing; unlinking keeps the history; sharing an
    asset across projects is links, never asset copies."""

    __tablename__ = "asset_links"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36))
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), index=True)
    entity_type: Mapped[str] = mapped_column(String(32), index=True)
    entity_id: Mapped[str] = mapped_column(String(36), index=True)
    relation: Mapped[str] = mapped_column(String(32), default="serves")
    added_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class FindingContext(Base):
    """Finding contextual attachment beyond project/version/component: the
    repository, service, deployment or asset where it was observed."""

    __tablename__ = "finding_contexts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36))
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id"), index=True)
    entity_type: Mapped[str] = mapped_column(String(32))
    entity_id: Mapped[str] = mapped_column(String(36))
    relation: Mapped[str] = mapped_column(String(32), default="observed_in")
    added_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

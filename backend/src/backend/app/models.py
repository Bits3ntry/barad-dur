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
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


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
    # A product or account that owns several repositories ("Aurea" holds the
    # frontend, backend, fx and document services). Free text on purpose: the
    # grouping is whatever the organization calls it, and it can be re-assigned
    # without a migration.
    group_name: Mapped[str | None] = mapped_column(String(128), nullable=True)


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
    # Owner and narrative fields the detail screen owes the reader. `assignee`
    # is a free identity (email or principal name) so API-key and human actors
    # share one column; My work resolves it against the caller.
    assignee: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    cwe: Mapped[str | None] = mapped_column(String(64), nullable=True)
    impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    reproduction: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Last run that actually evaluated this finding; closure requires it.
    last_evaluated_run_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, index=True)
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
    match_intel: Mapped[str | None] = mapped_column(String(32), nullable=True)
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
    # Inventory ownership. `classification_status` is deliberately separate from
    # scope authorization: confirming an asset is ours never grants a scan.
    project_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("projects.id"), nullable=True, index=True)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    classification_status: Mapped[str] = mapped_column(
        String(24), default="unclassified", index=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    archived_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
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
    """What the organization may audit or analyze: static positive list.

    A target is a *declaration*, not a running job: `capabilities` records what
    this row may later permit, and `scan_grants` remain the thing a collector
    checks before touching anything. Wildcards are rules — they never create a
    host; a concrete target links the canonical asset with source `scope`.
    """

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
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    source: Mapped[str] = mapped_column(String(32), default="manual")
    valid_from: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    valid_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    restrictions: Mapped[list] = mapped_column(JSON, default=list)
    capabilities: Mapped[list] = mapped_column(JSON, default=list)
    include_apex: Mapped[bool] = mapped_column(Boolean, default=False)
    asset_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("assets.id"), nullable=True, index=True)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ScopeExclusion(Base, TimestampMixin):
    """Negative scope entries; resolved view subtracts these from targets.

    An effective exclusion always wins, including over a wildcard target that
    covers it. Excluding a resource never deletes its inventory and never
    resolves its findings.
    """

    __tablename__ = "scope_exclusions"
    __table_args__ = (
        UniqueConstraint("org_id", "target_type", "value", name="uq_scope_exclusions_identity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    target_type: Mapped[str] = mapped_column(String(32))
    value: Mapped[str] = mapped_column(String(1024))
    reason: Mapped[str] = mapped_column(Text)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source: Mapped[str] = mapped_column(String(32), default="manual")
    status: Mapped[str] = mapped_column(String(32), default="active")
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)

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
    # What exactly is running here. A deployment points at an artifact (and
    # through it at a version); "in production" is read from these rows, never
    # from a flag on the version.
    artifact_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("artifacts.id"), nullable=True, index=True)
    application_component_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("application_components.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="active", index=True)
    deployed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    retired_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)

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


# ─────────────── BL-015: scan authorization engine ───────────────

class ScanGrant(Base):
    """An explicit, expiring, revocable authorization to run one or more
    capabilities against declared targets. Issuance and revocation both
    leave an audit-chain entry; revalidation never trusts past answers."""

    __tablename__ = "scan_grants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    principal: Mapped[str] = mapped_column(String(255), index=True)
    capabilities: Mapped[str] = mapped_column(String(255))
    tools: Mapped[str | None] = mapped_column(String(512), nullable=True)
    environment: Mapped[str | None] = mapped_column(String(64), nullable=True)
    conditions: Mapped[str | None] = mapped_column(Text, nullable=True)
    issued_by: Mapped[str] = mapped_column(String(255))
    justification: Mapped[str] = mapped_column(Text)
    policy_version: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    targets: Mapped[list["ScanGrantTarget"]] = relationship(
        "ScanGrantTarget", cascade="all, delete-orphan", lazy="selectin")


class ScanGrantTarget(Base):
    """One declared target of a grant (exact or wildcard-shaped)."""

    __tablename__ = "scan_grant_targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    grant_id: Mapped[str] = mapped_column(String(36), ForeignKey("scan_grants.id", ondelete="CASCADE"), index=True)
    target_type: Mapped[str] = mapped_column(String(32))
    target_value: Mapped[str] = mapped_column(String(1024))


# ─────────────── BL-040: occurrences ───────────────

class Occurrence(Base):
    """One verified sighting of one finding (per ingest/scan event). The
    finding row dedupes the weakness; occurrences preserve the sighting
    history with its context and evidence pointer."""

    __tablename__ = "occurrences"
    __table_args__ = (
        UniqueConstraint("finding_id", "sighting_key", name="uq_occurrence_sighting"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id"), index=True)
    project_version_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("project_versions.id"), nullable=True)
    ci_run_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("ci_runs.id"), nullable=True)
    tool: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source: Mapped[str | None] = mapped_column(String(32), nullable=True)
    sighting_key: Mapped[str] = mapped_column(String(64))
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ─────────────── BL-060: license management ───────────────

class ComponentLicense(Base):
    """One declared license of a component (multi-license aware; the
    component's single `license` column stays the summary)."""

    __tablename__ = "component_licenses"
    __table_args__ = (
        UniqueConstraint("component_id", "license_id", name="uq_component_license"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    component_id: Mapped[str] = mapped_column(String(36), ForeignKey("components.id"),
                                              index=True)
    license_id: Mapped[str] = mapped_column(String(255), index=True)
    source: Mapped[str] = mapped_column(String(32), default="sbom")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class LicensePolicy(Base, TimestampMixin):
    """org- or project-scoped allow/deny lists with an explicit unknown action."""

    __tablename__ = "license_policies"
    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_license_policies_name"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    name: Mapped[str] = mapped_column(String(255))
    scope_type: Mapped[str] = mapped_column(String(16), default="org")
    scope_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    allow_list: Mapped[str | None] = mapped_column(Text, nullable=True)
    deny_list: Mapped[str | None] = mapped_column(Text, nullable=True)
    unknown_action: Mapped[str] = mapped_column(String(16), default="warn")
    status: Mapped[str] = mapped_column(String(32), default="active")

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class LicenseException(Base, TimestampMixin):
    """Explicit, expiring, audited waiver for one (component identity, license)."""

    __tablename__ = "license_exceptions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    component_identity: Mapped[str] = mapped_column(String(1100), index=True)
    license_id: Mapped[str] = mapped_column(String(255))
    reason: Mapped[str] = mapped_column(Text)
    approved_by: Mapped[str] = mapped_column(String(255))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ─────────────── BL-055: quality gate policies ───────────────

class GatePolicy(Base, TimestampMixin):
    """Deterministic, versioned gate: severity threshold plus optional KEV and
    license-denial blocks. Project policies override org policies."""

    __tablename__ = "gate_policies"
    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_gate_policies_name"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    name: Mapped[str] = mapped_column(String(255))
    scope_type: Mapped[str] = mapped_column(String(16), default="org")
    scope_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    max_severity: Mapped[str] = mapped_column(String(16), default="HIGH")
    block_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    block_license_denied: Mapped[bool] = mapped_column(Boolean, default=False)
    include_suppressed: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(32), default="active")

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ─────────────── BL-090: asset snapshots ───────────────

class AssetSnapshot(Base):
    """One observation of an asset at a point in time (DNS/TLS/tech/service
    metadata as JSON). Change detection diffs consecutive observations; a
    snapshot never implies scan authorization."""

    __tablename__ = "asset_snapshots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"),
                                          index=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    source: Mapped[str] = mapped_column(String(64), default="manual")
    data: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ─────────────── BL-070: pentest management ───────────────

PENTEST_ENGAGEMENT_STATUSES = {"draft", "active", "completed", "cancelled"}
PENTEST_FINDING_STATUSES = {"open", "in_remediation", "retest_pending",
                            "verified", "closed", "false_positive"}


class PentestEngagement(Base, TimestampMixin):
    """One pentest engagement (campaign) scoped to a project/version."""

    __tablename__ = "pentest_engagements"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    project_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("projects.id"), nullable=True)
    project_version_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("project_versions.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(255))
    lead: Mapped[str | None] = mapped_column(String(255), nullable=True)
    methodology: Mapped[str | None] = mapped_column(String(255), nullable=True)
    scope_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="draft")
    starts_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PentestTest(Base, TimestampMixin):
    """One test/procedure inside an engagement."""

    __tablename__ = "pentest_tests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("pentest_engagements.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(255))
    methodology: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tester: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PentestFinding(Base, TimestampMixin):
    """Manual/tool-imported pentest finding with HTTP evidence and retest."""

    __tablename__ = "pentest_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("pentest_engagements.id", ondelete="CASCADE"),
        index=True)
    test_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("pentest_tests.id"), nullable=True)
    asset_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("assets.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(512))
    reported_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="MEDIUM")
    cvss: Mapped[str | None] = mapped_column(String(16), nullable=True)
    method: Mapped[str] = mapped_column(String(64), default="manual")
    target: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    reproduction: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="open")
    verification_evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    verified_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ─────────────── BL-050: Jira bridge ───────────────

class JiraLink(Base, TimestampMixin):
    """Mapping finding <-> Jira issue. Barad-dûr owns findings; Jira owns its
    own workflow — a Done ticket never closes a finding by itself."""

    __tablename__ = "jira_links"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id"), index=True)
    project_key: Mapped[str] = mapped_column(String(64))
    issue_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    issue_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    external_status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    external_assignee: Mapped[str | None] = mapped_column(String(255), nullable=True)
    sync_state: Mapped[str] = mapped_column(String(32), default="pending")
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class JiraOutbox(Base):
    """Idempotent outbound queue (dedupe_key unique per org)."""

    __tablename__ = "jira_outbox"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    link_id: Mapped[str] = mapped_column(String(36), ForeignKey("jira_links.id"))
    action: Mapped[str] = mapped_column(String(32))
    payload: Mapped[str] = mapped_column(Text)
    dedupe_key: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# ─────────────── BL-080: security regression suites ───────────────

class RegressionTest(Base, TimestampMixin):
    """Replayable HTTP check with assertions; execution requires an active
    authorization grant for its target (BL-015)."""

    __tablename__ = "regression_tests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    project_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("projects.id"), nullable=True)
    project_version_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("project_versions.id"), nullable=True)
    suite: Mapped[str] = mapped_column(String(64), default="default")
    name: Mapped[str] = mapped_column(String(255))
    method: Mapped[str] = mapped_column(String(16), default="GET")
    url: Mapped[str] = mapped_column(String(2048))
    headers: Mapped[str] = mapped_column(Text, default="{}")
    body: Mapped[str | None] = mapped_column(Text, nullable=True)
    assertions: Mapped[str] = mapped_column(Text, default="[]")
    expected_outcome: Mapped[str] = mapped_column(String(16), default="pass")
    source_finding_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("pentest_findings.id"), nullable=True)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RegressionRun(Base):
    __tablename__ = "regression_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    test_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("regression_tests.id", ondelete="CASCADE"), index=True)
    project_version_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("project_versions.id"), nullable=True)
    result: Mapped[str] = mapped_column(String(16))
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reintroduced: Mapped[bool] = mapped_column(Boolean, default=False)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ran_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ─────────────── BL-020: orchestration (Shauron management side) ───────────────

class Scanner(Base, TimestampMixin):
    __tablename__ = "scanners"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_scanners_org_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    name: Mapped[str] = mapped_column(String(64))
    display_name: Mapped[str] = mapped_column(String(128))
    capability: Mapped[str] = mapped_column(String(64))
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    adapter: Mapped[str] = mapped_column(String(64), default="cli")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class Worker(Base):
    __tablename__ = "workers"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_workers_org_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    name: Mapped[str] = mapped_column(String(128))
    capabilities: Mapped[str] = mapped_column(Text, default="[]")
    labels: Mapped[str] = mapped_column(Text, default="{}")
    max_concurrent: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(16), default="online")
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_heartbeat: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    project_version_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("project_versions.id"), nullable=True)
    scanner: Mapped[str] = mapped_column(String(64))
    capability: Mapped[str] = mapped_column(String(64))
    principal: Mapped[str] = mapped_column(String(255))
    environment: Mapped[str | None] = mapped_column(String(128), nullable=True)
    targets: Mapped[str] = mapped_column(Text, default="[]")
    profile: Mapped[str] = mapped_column(Text, default="{}")
    status: Mapped[str] = mapped_column(String(16), default="queued")
    priority: Mapped[int] = mapped_column(Integer, default=5)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)
    worker_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("workers.id"), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    authorization: Mapped[str | None] = mapped_column(Text, nullable=True)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class JobArtifact(Base):
    __tablename__ = "job_artifacts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    job_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(32))
    content: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ─────────────── BL-040b part 2: code review ───────────────

class CodeFile(Base):
    """Source snapshot pushed by CI for one ref (never fetched silently)."""

    __tablename__ = "code_files"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    repository_id: Mapped[str] = mapped_column(String(36), ForeignKey("repositories.id"))
    ref: Mapped[str] = mapped_column(String(128))
    path: Mapped[str] = mapped_column(String(1024))
    content: Mapped[str] = mapped_column(Text)
    content_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PullRequest(Base, TimestampMixin):
    __tablename__ = "pull_requests"
    __table_args__ = (UniqueConstraint("org_id", "repository_id", "number",
                                       name="uq_pr_org_repo_number"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    project_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("projects.id"), nullable=True)
    project_version_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("project_versions.id"), nullable=True)
    repository_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("repositories.id"), nullable=True)
    number: Mapped[int] = mapped_column(Integer)
    title: Mapped[str | None] = mapped_column(String(512), nullable=True)
    branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    base_branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    head_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="open")
    gate_verdict: Mapped[str | None] = mapped_column(String(16), nullable=True)
    gate_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SastBaseline(Base):
    """A named set of accepted SAST fingerprints; inert until approved."""

    __tablename__ = "sast_baselines"
    __table_args__ = (UniqueConstraint("org_id", "name",
                                       name="uq_sast_baseline_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    name: Mapped[str] = mapped_column(String(128))
    repository_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("repositories.id"), nullable=True)
    project_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("projects.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="draft")
    entries: Mapped[list] = mapped_column(JSON, default=list)
    counters: Mapped[dict] = mapped_column(JSON, default=dict)
    source_pr_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_by: Mapped[str] = mapped_column(String(255))
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow)


class PrFinding(Base):
    __tablename__ = "pr_findings"
    __table_args__ = (UniqueConstraint("pr_id", "finding_id", name="uq_pr_finding"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    pr_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("pull_requests.id", ondelete="CASCADE"))
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id"))
    classification: Mapped[str] = mapped_column(String(16), default="new")
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ─────────────── users & sessions ───────────────

USER_ROLES = {"owner", "admin", "analyst", "viewer"}


class User(Base, TimestampMixin):
    """A human principal. API keys stay the org-level service identity."""

    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("org_id", "email", name="uq_users_org_email"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    email: Mapped[str] = mapped_column(String(320))
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    role: Mapped[str] = mapped_column(String(16), default="viewer")
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="active")
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)


class OidcState(Base):
    __tablename__ = "oidc_states"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    state_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    nonce: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)


class ScanSchedule(Base, TimestampMixin):
    """Recurring job definition; a tick queues due jobs through the same
    authorization path as manual ones (never bypassing BL-015)."""

    __tablename__ = "scan_schedules"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_schedules_org_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    name: Mapped[str] = mapped_column(String(128))
    scanner: Mapped[str] = mapped_column(String(64))
    capability: Mapped[str] = mapped_column(String(64))
    principal: Mapped[str] = mapped_column(String(255))
    targets: Mapped[str] = mapped_column(Text, default="[]")
    environment: Mapped[str | None] = mapped_column(String(128), nullable=True)
    profile: Mapped[str] = mapped_column(Text, default="{}")
    kind: Mapped[str] = mapped_column(String(16), default="scan")
    asset_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("assets.id"), nullable=True)
    interval_minutes: Mapped[int] = mapped_column(Integer, default=1440)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_job_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class WorkerToken(Base):
    """A worker's own credential: only the scan-job endpoints accept it, so a
    compromised worker cannot read findings, grants or audit history."""

    __tablename__ = "worker_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    worker_id: Mapped[str] = mapped_column(String(36), ForeignKey("workers.id"))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    label: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class NotificationChannel(Base, TimestampMixin):
    """Webhook destination; deliveries are signed with the channel secret."""

    __tablename__ = "notification_channels"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_channels_org_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    name: Mapped[str] = mapped_column(String(128))
    kind: Mapped[str] = mapped_column(String(32), default="webhook")
    url: Mapped[str] = mapped_column(String(2048))
    secret: Mapped[str] = mapped_column(String(255))
    events: Mapped[str] = mapped_column(Text, default="[]")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)




class Notification(Base, TimestampMixin):
    """An in-app notification event for the user."""
    __tablename__ = "notifications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"),
                                       index=True)
    channel: Mapped[str | None] = mapped_column(String(128))
    event: Mapped[str] = mapped_column(String(128))
    count: Mapped[int] = mapped_column(Integer, default=1)
    read: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    payload: Mapped[str | None] = mapped_column(Text, nullable=True)


class NotificationPreference(Base, TimestampMixin):
    """Per-user notification preferences."""
    __tablename__ = "notification_preferences"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"),
                                       index=True, unique=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"),
                                        index=True)
    email_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    push_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    sla_breach: Mapped[bool] = mapped_column(Boolean, default=True)
    assignment: Mapped[bool] = mapped_column(Boolean, default=True)
    retest_request: Mapped[bool] = mapped_column(Boolean, default=True)
    jira_sync_error: Mapped[bool] = mapped_column(Boolean, default=True)

class NotificationDelivery(Base, TimestampMixin):
    __tablename__ = "notification_deliveries"
    __table_args__ = (UniqueConstraint("org_id", "dedupe_key", name="uq_delivery_dedupe"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    channel_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("notification_channels.id", ondelete="CASCADE"),
        index=True)
    event: Mapped[str] = mapped_column(String(64))
    dedupe_key: Mapped[str] = mapped_column(String(128))
    payload: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SbomBaseline(Base):
    """Frozen component set for a project version; future ingests diff against it."""

    __tablename__ = "sbom_baselines"
    __table_args__ = (UniqueConstraint("project_version_id", name="uq_baseline_version"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    project_version_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("project_versions.id"))
    components: Mapped[str] = mapped_column(Text)
    component_count: Mapped[int] = mapped_column(Integer, default=0)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
class TrivyDbUpdate(Base, TimestampMixin):
    """Record of Trivy DB fetch/update; called by the offline updater."""

    __tablename__ = "trivy_db_updates"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    status: Mapped[str] = mapped_column(
        String(32), default="pending", index=True)
    target_filename: Mapped[str | None] = mapped_column(String(512), nullable=True)
    target_size: Mapped[int] = mapped_column(Integer, default=0)
    target_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    header_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_scheduled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    last_successful_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)





# ─────────────── v0 inventory: application components, artifacts ───────────────
#
# A technical component (backend/frontend/worker) is *not* a software package:
# `Component` is a purl-identified dependency, `Service` is a deployable, and
# this is the code unit the application is made of. Keeping them apart is what
# makes "which package is in which build" answerable later.

APP_COMPONENT_KINDS = {"backend", "frontend", "worker", "other"}
ASSET_CLASSIFICATION = {"unclassified", "pending", "confirmed", "external", "discarded"}
DEPLOYMENT_STATUSES = {"planned", "active", "retired"}


class ApplicationComponent(Base):
    """One code unit of a project (AUREA backend, AUREA web, workers)."""

    __tablename__ = "application_components"
    __table_args__ = (
        UniqueConstraint("project_id", "slug", name="uq_app_component_slug"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), index=True)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"), index=True)
    kind: Mapped[str] = mapped_column(String(24), default="backend")
    name: Mapped[str] = mapped_column(String(255))
    slug: Mapped[str] = mapped_column(String(128))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Artifact(Base):
    """The exact build: digest, provenance and the SBOM that describes it.

    A version can have many artifacts, and only a deployment (not the version
    row) says what is running where.
    """

    __tablename__ = "artifacts"
    __table_args__ = (
        UniqueConstraint("org_id", "digest", name="uq_artifact_digest"),
        Index("ix_artifacts_version", "project_version_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), index=True)
    project_version_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("project_versions.id"), nullable=True)
    application_component_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("application_components.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(255))
    digest: Mapped[str | None] = mapped_column(String(128), nullable=True)
    digest_algorithm: Mapped[str | None] = mapped_column(String(32), nullable=True)
    provenance: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source: Mapped[str] = mapped_column(String(32), default="import")
    build_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ─────────────── v0 inventory: groups + stakeholders ───────────────
#
# Inventory groups organize *resources*. They are unrelated to access groups
# (which do not exist yet): membership here never grants a permission.

INVENTORY_GROUP_ROLES = {"owner", "collaborator"}


class InventoryGroup(Base):
    __tablename__ = "inventory_groups"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_inventory_group_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class InventoryGroupMember(Base):
    """Asset ↔ group edge. Removal is soft (`removed_at`) so activity survives."""

    __tablename__ = "inventory_group_members"
    __table_args__ = (UniqueConstraint("group_id", "asset_id", name="uq_group_asset"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    group_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("inventory_groups.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), index=True)
    added_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    removed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)


class InventoryGroupStakeholder(Base):
    __tablename__ = "inventory_group_stakeholders"
    __table_args__ = (UniqueConstraint("group_id", "actor", name="uq_group_stakeholder"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    group_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("inventory_groups.id", ondelete="CASCADE"), index=True)
    actor: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(24), default="collaborator")
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ─────────────── v0 findings: owner, comments, evidence ───────────────

class FindingComment(Base):
    __tablename__ = "finding_comments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    author: Mapped[str | None] = mapped_column(String(255), nullable=True)
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FindingAttachment(Base):
    """Evidence attachment. Contents live in the row (bounded), never on disk.

    `redaction_state` starts `unreviewed`: v0 stores the bytes as uploaded and
    marks them; automated secret detection is not implemented and must not be
    implied by a clean-looking badge.
    """

    __tablename__ = "finding_attachments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    media_type: Mapped[str] = mapped_column(String(128), default="text/plain")
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64))
    content: Mapped[str] = mapped_column(Text)
    redaction_state: Mapped[str] = mapped_column(String(24), default="unreviewed")
    added_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ─────────────── v0 analysis coverage ───────────────
#
# "Not seen by a scan" only means "fixed" when the scan actually covered the
# thing. Runs record what they evaluated; closure is a separate, explicit step
# that refuses to act on diff/partial coverage.

ANALYSIS_COVERAGES = {"full", "diff", "partial", "unknown"}
CLOSABLE_COVERAGES = {"full"}


class AnalysisRun(Base):
    """One import/scan: tool, revision, coverage and what it evaluated."""

    __tablename__ = "analysis_runs"
    __table_args__ = (
        Index("ix_analysis_runs_project", "project_id", "project_version_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), index=True)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"))
    project_version_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("project_versions.id"), nullable=True)
    tool: Mapped[str] = mapped_column(String(64))
    tool_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    coverage: Mapped[str] = mapped_column(String(16), default="unknown")
    source: Mapped[str] = mapped_column(String(32), default="import")
    revision: Mapped[str | None] = mapped_column(String(128), nullable=True)
    branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    base_revision: Mapped[str | None] = mapped_column(String(128), nullable=True)
    evaluated: Mapped[dict] = mapped_column(JSON, default=dict)
    receipt: Mapped[dict] = mapped_column(JSON, default=dict)
    findings_seen: Mapped[int] = mapped_column(Integer, default=0)
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

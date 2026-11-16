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
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    LargeBinary,
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
    # Profile captured during onboarding. Free text on purpose: the product the
    # organization runs is whatever it calls it, and none of these fields feed
    # analysis or authorization.
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    website: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # `logo` holds either an https URL or a small inline data URL (the console
    # downscales the file it uploads). Never fetched server-side.
    logo: Mapped[str | None] = mapped_column(Text, nullable=True)
    onboarding_completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)


class ApiKey(Base, TimestampMixin):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    label: Mapped[str] = mapped_column(String(255), default="")

    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# crown → high → normal → low. Anything else (including null) is `unclassified`,
# and the API says so rather than guessing a middle value.
CRITICALITY_LEVELS = {"crown", "high", "normal", "low"}


class Project(Base, TimestampMixin):
    __tablename__ = "projects"
    __table_args__ = (UniqueConstraint("org_id", "slug", name="uq_projects_org_slug"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    name: Mapped[str] = mapped_column(String(255))
    slug: Mapped[str] = mapped_column(String(255))
    # Inventory context: what this product is for, and who answers for it. Free
    # text because a project is an organizational unit, not a schema.
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # A product or account that owns several repositories ("Aurea" holds the
    # frontend, backend, fx and document services). Free text on purpose: the
    # grouping is whatever the organization calls it, and it can be re-assigned
    # without a migration.
    group_name: Mapped[str | None] = mapped_column(String(128), nullable=True)


class ProjectVersion(Base, TimestampMixin):
    """A version of one code unit.

    `component_id` NULL means a product-wide release (several components shipped
    as one train). Scoping it to the component is what lets the backend's SBOM
    and the web's SBOM carry the same label without colliding.
    """

    __tablename__ = "project_versions"
    __table_args__ = (
        UniqueConstraint("project_id", "component_id", "version",
                         name="uq_project_version_scope"),
        Index("ix_project_versions_component_id", "component_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"))
    component_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("application_components.id"), nullable=True)
    version: Mapped[str] = mapped_column(String(255))


class SbomImport(Base, TimestampMixin):
    __tablename__ = "sbom_imports"
    __table_args__ = (
        UniqueConstraint("project_version_id", "content_sha256", name="uq_sbom_import_idempotent"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    project_version_id: Mapped[str] = mapped_column(String(36), ForeignKey("project_versions.id"))
    # The exact build this document describes, when the caller declares it.
    artifact_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("artifacts.id"), nullable=True, index=True)
    content_sha256: Mapped[str] = mapped_column(String(64))
    scan_job_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scan_jobs.id"), nullable=True, index=True)
    source: Mapped[str] = mapped_column(String(32), default="api")
    filename: Mapped[str | None] = mapped_column(String(512), nullable=True)

    components_received: Mapped[int] = mapped_column(Integer, default=0)
    components_created: Mapped[int] = mapped_column(Integer, default=0)
    components_updated: Mapped[int] = mapped_column(Integer, default=0)
    components_skipped: Mapped[int] = mapped_column(Integer, default=0)
    links_created: Mapped[int] = mapped_column(Integer, default=0)
    # An SBOM is also an advisory list. Counting only components is what let a
    # 67-CVE document read as "imported successfully, nothing found".
    vulnerabilities_received: Mapped[int] = mapped_column(Integer, default=0)
    vulnerabilities_created: Mapped[int] = mapped_column(Integer, default=0)
    vulnerabilities_refreshed: Mapped[int] = mapped_column(Integer, default=0)
    vulnerabilities_unresolved: Mapped[int] = mapped_column(Integer, default=0)


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
    # Nullable since F3 (D29): an asset-only finding — a WordPress behind a domain —
    # is a real thing, and inventing a project to hold it was the lie this column
    # used to force.
    project_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("projects.id"), nullable=True)
    asset_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("assets.id"), nullable=True, index=True)
    # A run's claim: the scan job that said so. Kept so a finding can be traced to
    # the evidence that produced it even while it belongs to no asset yet.
    origin_run_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scan_jobs.id"), nullable=True, index=True)
    # The autonomous path's three ids: the mission that authorised the run, the task
    # that decided it, and the candidate the gates settled. They are what turns a
    # claim into a story — without them the trace lives in `agent_task_events` and
    # the finding cannot reach it.
    agent_mission_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, index=True)
    agent_task_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, index=True)
    agent_candidate_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True)
    # Who found it. Not the same question as `source` (which tool said so): a pentest
    # row and a scanner row can share a tool and still need different weight.
    origin: Mapped[str] = mapped_column(String(32), default="scanner", index=True)
    # Human verdict. The agent can only create `new`; a person moves it on.
    triage_status: Mapped[str] = mapped_column(String(16), default="triaged", index=True)
    # Proof, on its own axis: hypothesis | static | observed | demonstrated.
    evidence_level: Mapped[str] = mapped_column(String(16), default="observed")
    # Impact, on its own axis: none | attempted | reproduced | effect_proven.
    exploit_state: Mapped[str] = mapped_column(String(16), default="none")
    evidence_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("finding_attachments.id"), nullable=True)
    triaged_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    triaged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    triage_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    # The class says WHAT it is; the vector says HOW it must be closed. A CVE is
    # closed by upgrading the package, a credential by rotating it, a code defect
    # by changing the code — and putting them in one bucket without this makes
    # remediation right for a third of the rows.
    vector: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
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
    # ── the fingerprint of a hand-written finding ──
    # A pentest row is not a title and a url: it names the weakness class, the
    # product, the exact endpoint, the session needed to reach it, the raw request
    # that proves it, and what we expected instead. Without these the report cannot
    # be reproduced by anyone who was not in the room.
    http_method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    endpoint: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    auth_required: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    auth_profile_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("auth_profiles.id"), nullable=True)
    expected_result: Mapped[str | None] = mapped_column(Text, nullable=True)
    observed_result: Mapped[str | None] = mapped_column(Text, nullable=True)
    validation_output: Mapped[str | None] = mapped_column(Text, nullable=True)
    proof_request: Mapped[str | None] = mapped_column(Text, nullable=True)
    proof_response: Mapped[str | None] = mapped_column(Text, nullable=True)
    # The product the weakness lives in: a crown jewel, not the domain that serves it.
    product_component_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("application_components.id"), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuthProfile(Base):
    """A reusable way in: bearer, cookie, header, form login.

    The session recipe belongs to the engagement, not to one finding — a pentest
    reaches forty endpoints through the same login, and repeating the token in forty
    rows is how credentials end up in fifty places nobody can rotate.
    """

    __tablename__ = "auth_profiles"
    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_auth_profiles_org_name"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    # bearer | cookie | header | basic | form_login | oauth | mtls | none
    kind: Mapped[str] = mapped_column(String(32), default="bearer")
    headers: Mapped[str | None] = mapped_column(Text, nullable=True)
    login_steps: Mapped[str | None] = mapped_column(Text, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RepeatRun(Base):
    """One executed Repeat chain for a finding: what was sent, what came back.

    A repeater without history is a scratchpad: the run that reproduced the bug at
    10:04 is the evidence, and it has to survive the tab being closed. The chain is
    stored with the requests as they were **written** (`Authorization: Bearer
    {{token}}`) and the responses as they came back, which is why this row is the
    one place a token may appear in the body — that is what was proved.
    """

    __tablename__ = "repeat_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"),
                                        index=True)
    finding_id: Mapped[str | None] = mapped_column(String(36),
                                                   ForeignKey("findings.id"),
                                                   nullable=True, index=True)
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # ok | denied | error
    result: Mapped[str] = mapped_column(String(16), default="ok")
    steps: Mapped[str | None] = mapped_column(Text, nullable=True)
    variables: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


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
    """One known-exploited CVE mirrored locally, merged from every catalogue.

    The feed carries vendor, product, vulnerability name and description; discarding
    them left a list of ids that could be looked up but never searched, so "what came
    out this week and does it touch anything I run" had no answer.

    The row is keyed on the CVE, not on the publisher: CISA, VulnCheck and the EU
    list often say the same CVE is being exploited, and stacking three rows would
    break the join every other screen makes. `sources` keeps the provenance
    ("cisa-kev,eu-kev") and `exploitation_type`/`euvd_id`/`notes` keep what only
    the EU list publishes — which kind of actor is using it, and the report.
    """

    __tablename__ = "kev_entries"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    # The four fields that make the row readable and matchable. `name` is the same
    # string as `title`; the duplicate keeps older screens working and is written by
    # the same sync.
    name: Mapped[str | None] = mapped_column(Text, nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    required_action: Mapped[str | None] = mapped_column(Text, nullable=True)
    ransomware: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cwes: Mapped[str | None] = mapped_column(String(255), nullable=True)
    date_added: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    due_date: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Comma-separated slugs of the catalogues that list this CVE, in authority
    # order. Empty on rows imported before the mirror knew there was more than one
    # catalogue; the migration backfills them as `cisa-kev`.
    sources: Mapped[str | None] = mapped_column(String(255), nullable=True)
    exploitation_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    euvd_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # CISA's `notes` and the EU list's report link answer the same question
    # ("what is the evidence?") from different sides, so they cannot share a
    # column: whichever catalogue wrote first would erase the other.
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    eu_evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class KevFeedState(Base):
    """Whether a catalogue answered the last time the mirror asked it.

    A merged row cannot say which source is stale — "1.779 rows" is the same
    number whether CISA answered ten minutes ago or the EU list has been failing
    for a week. One row per registry slug makes the difference visible, and lets
    "never synced" stay distinguishable from "synced, then broke".
    """

    __tablename__ = "kev_feed_state"

    source: Mapped[str] = mapped_column(String(32), primary_key=True)
    label: Mapped[str | None] = mapped_column(String(64), nullable=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_ok_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True),
                                                       nullable=True)
    last_ok_rows: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_error_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True),
                                                          nullable=True)


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
    # Inventory layer (onboarding v2): what the team *declares* is running here,
    # before any scan exists. `version_label` is the declared version; an import
    # or a health probe may confirm or replace it, and `source` says which.
    version_label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # The version row this deployment runs. `version_label` mirrors it for
    # display; matching by string is what used to orphan a deployment on rename.
    version_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("project_versions.id"), nullable=True, index=True)
    exposure: Mapped[str] = mapped_column(String(16), default="unknown")
    requires_auth: Mapped[bool] = mapped_column(Boolean, default=False)
    source: Mapped[str] = mapped_column(String(24), default="manual")
    last_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    last_check_status: Mapped[str | None] = mapped_column(String(24), nullable=True)
    last_check_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="active", index=True)
    deployed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    retired_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AssetGeo(Base):
    """Where an address sits, cached per asset and address.

    Geolocation belongs to the address, not to the name: ten subdomains on one box
    share it. Caching it here keeps the asset page fast and lets it say when the
    lookup happened — a location without a moment is a rumour. Nothing is fetched
    unless `PLATFORM_GEOIP_URL` is configured.
    """

    __tablename__ = "asset_geo"
    __table_args__ = (UniqueConstraint("asset_id", "address", name="uq_asset_geo_asset_address"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"))
    address: Mapped[str] = mapped_column(String(64))
    data: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    fetched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


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
    leave an audit-chain entry; revalidation never trusts past answers.

    A grant is also the *request*: declaring an asset emits a row with
    `status="requested"`, which the decision engine ignores (it only reads
    `active`), and an administrator approves — possibly widening its scope —
    from the Grants screen. That keeps one object and one place for authority
    instead of a second "request" table beside the ledger.
    """

    __tablename__ = "scan_grants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    principal: Mapped[str] = mapped_column(String(255), index=True)
    capabilities: Mapped[str] = mapped_column(String(255))
    # The human-facing bundle ("simple scan", "advanced scan", "red teaming").
    # `capabilities` stays the machine truth the engine reads; the level is what
    # the operator chose, and the two are kept in step on every write.
    level: Mapped[str] = mapped_column(String(16), default="simple")
    tools: Mapped[str | None] = mapped_column(String(512), nullable=True)
    environment: Mapped[str | None] = mapped_column(String(64), nullable=True)
    conditions: Mapped[str | None] = mapped_column(Text, nullable=True)
    issued_by: Mapped[str] = mapped_column(String(255))
    justification: Mapped[str] = mapped_column(Text)
    policy_version: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    # Who asked (an asset declaration) and who answered (an administrator).
    requested_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    # The asset whose declaration produced the request, so the console can show
    # "this domain is waiting for authorization" without guessing by value.
    asset_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("assets.id"), nullable=True, index=True)
    source: Mapped[str] = mapped_column(String(24), default="manual")
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
    # F3: the queue row this engagement finding became, so the same object has one
    # identity across two screens (D29).
    ingested_finding_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("findings.id"), nullable=True, index=True)

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
    # The campaign this run belongs to. A tool is launched *into* a cycle: without
    # it, a run's findings have no reference to be judged against, and the review
    # would be typed by hand. System jobs (advisory clock, enrichment) leave it null.
    cycle_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("cycles.id"), nullable=True, index=True)
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

    # ── v01 scan flows: what this job is, and what it points at ───────────
    # `origin` says who asked (ci/cli/console/api); `executor` says who holds the
    # process, which is what decides whether this platform can kill it.
    origin: Mapped[str] = mapped_column(String(16), default="console")
    executor: Mapped[str] = mapped_column(String(16), default="shauron")
    tasks: Mapped[str] = mapped_column(Text, default="[]")
    subject: Mapped[str] = mapped_column(Text, default="{}")
    ticket_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    daemon_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    contract_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    deadline_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    evidence_state: Mapped[str] = mapped_column(String(16), default="none")
    upload_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_event_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    revived_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    revival_count: Mapped[int] = mapped_column(Integer, default=0)
    cancelled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)


class ScanAttributionIntake(Base):
    """Evidence we received but cannot honestly attach to a component version yet."""

    __tablename__ = "scan_attribution_intakes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), index=True)
    project_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("projects.id"), nullable=True)
    repository_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("repositories.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="needs_attribution", index=True)
    reason: Mapped[str] = mapped_column(String(128))
    subject: Mapped[str] = mapped_column(Text, default="{}")
    candidate_component_ids: Mapped[str] = mapped_column(Text, default="[]")
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    assigned_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    assigned_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    assignment_note: Mapped[str | None] = mapped_column(Text, nullable=True)


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


class OrganizationMember(Base):
    """A person's seat in one organisation.

    `users.org_id` used to be the whole answer, which made "change organisation"
    impossible: the row *was* the membership. Now the user is a person and this
    table says where they may work — `role` here, not on the user, decides what
    they may do in that organisation.
    """

    __tablename__ = "organization_members"
    __table_args__ = (UniqueConstraint("org_id", "user_id", name="uq_org_members"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"),
                                        index=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), index=True)
    role: Mapped[str] = mapped_column(String(16), default="viewer")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


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
    # Optional second factor. A secret exists from enrolment, but only
    # `totp_enabled_at` makes it required at login — that is what separates an
    # abandoned enrolment from an active one.
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    totp_enabled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MfaChallenge(Base):
    """Short-lived half-session between "password ok" and "code ok"."""

    __tablename__ = "mfa_challenges"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)


class MfaRecoveryCode(Base):
    """One-time codes shown once at activation; only their hashes persist."""

    __tablename__ = "mfa_recovery_codes"
    __table_args__ = (Index("ix_mfa_recovery_user", "user_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"))
    code_hash: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)


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
    refresh_token_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True)
    refresh_token_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)


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


class ScanWorkflow(Base, TimestampMixin):
    """A workflow an organisation writes: the catalog's document shape, its rules.

    Stored as the document it is — stages and limits as JSON — rather than as
    rows per stage: the platform never queries a stage on its own, it hands the
    whole thing to the resolver, and the resolver's contract is the document.
    """

    __tablename__ = "scan_workflows"
    __table_args__ = (UniqueConstraint("org_id", "slug", name="uq_workflows_org_slug"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    #: `org.<name>` — the prefix is what tells the resolver this is not a catalog
    #: profile, and it is part of every plan that names it.
    slug: Mapped[str] = mapped_column(String(96))
    label: Mapped[str] = mapped_column(String(128))
    question: Mapped[str] = mapped_column(Text, default="")
    target_kind: Mapped[str] = mapped_column(String(32), default="domain")
    level: Mapped[str] = mapped_column(String(16), default="simple")
    plane: Mapped[str] = mapped_column(Text, default="[]")
    stages: Mapped[str] = mapped_column(Text, default="[]")
    limits: Mapped[str] = mapped_column(Text, default="{}")
    #: Which catalog profile it was cloned from, when it was. Provenance, not a
    #: parent: editing the catalog never rewrites an organisation's workflow.
    cloned_from: Mapped[str | None] = mapped_column(String(96), nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), default="console")
    archived: Mapped[bool] = mapped_column(Boolean, default=False)


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


class DeviceAuthorization(Base):
    """A terminal asking to become a session (RFC 8628, simplified).

    The device shows a short code, a human approves it in the console, and the
    terminal trades its secret for a real session. The secret is stored **hashed**
    — a leaked table must not be a leaked set of credentials — while the short
    code is stored in clear because it is only useful together with that secret
    and only for eight minutes.

    Approval is a human decision by an owner or an admin, and it is the only place
    a CLI session is born: the grant engine never sees this table.
    """

    __tablename__ = "device_authorizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    user_code: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    device_code_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    hostname: Mapped[str | None] = mapped_column(String(128), nullable=True)
    platform: Mapped[str | None] = mapped_column(String(64), nullable=True)
    agent: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Filled by the approver, so the session that comes out is theirs.
    org_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("organizations.id"), nullable=True)
    user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=True)
    decided_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    last_polled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    polls: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


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
    # Business context: the jewel is the **component** — AUREA > Backend, not AUREA
    # and not the domain in front of it. A project is a container; a component is
    # what the business runs. `crown` is what the threat model is built for; null
    # means nobody judged it, and the API says `unclassified` instead of guessing.
    criticality: Mapped[str | None] = mapped_column(
        String(16), nullable=True, index=True)
    business_service: Mapped[str | None] = mapped_column(String(255), nullable=True)
    criticality_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    criticality_set_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    criticality_updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
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
    # Which remote this code came from, and the pull request when the report was
    # produced for one: the pair a reviewer needs to reopen the same diff.
    repository_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("repositories.id"), nullable=True, index=True)
    pull_request: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Which scan flow produced this evidence. NULL means a plain import: allowed,
    # attributable to a person, and structurally unable to close a finding.
    scan_job_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scan_jobs.id"), nullable=True, index=True)
    evaluated: Mapped[dict] = mapped_column(JSON, default=dict)
    receipt: Mapped[dict] = mapped_column(JSON, default=dict)
    findings_seen: Mapped[int] = mapped_column(Integer, default=0)
    # Comparison and viewer material. `base_run_id` is what "new" is relative
    # to; without it nothing is classified new or resolved.
    base_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    report_format: Mapped[str | None] = mapped_column(String(16), nullable=True)
    rules: Mapped[list] = mapped_column(JSON, default=list)
    uninterpreted: Mapped[dict] = mapped_column(JSON, default=dict)
    diff_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AnalysisFile(Base):
    """One file of an analysis: the code we can actually show.

    A JSON report alone does not give us the source; when the importer supplies
    no content the viewer says so instead of drawing an empty file.
    """

    __tablename__ = "analysis_files"
    __table_args__ = (UniqueConstraint("run_id", "path", name="uq_analysis_file_path"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("analysis_runs.id", ondelete="CASCADE"), index=True)
    path: Mapped[str] = mapped_column(String(1024))
    content: Mapped[str | None] = mapped_column(Text, nullable=True)
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    line_count: Mapped[int] = mapped_column(Integer, default=0)
    kind: Mapped[str] = mapped_column(String(16), default="analyzed")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AnalysisFinding(Base):
    """A result inside one analysis, classified against a comparable baseline."""

    __tablename__ = "analysis_findings"
    # One finding identity can fire on several lines; the viewer shows each
    # location, so uniqueness includes the line.
    __table_args__ = (UniqueConstraint("run_id", "finding_id", "line",
                                       name="uq_analysis_finding_line"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("analysis_runs.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id"), index=True)
    path: Mapped[str] = mapped_column(String(1024))
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    end_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cwe: Mapped[str | None] = mapped_column(String(64), nullable=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    # new | persistent | resolved | no_reference — no_reference means there was
    # no comparable baseline, not that the finding is new.
    classification: Mapped[str] = mapped_column(String(24), default="no_reference")
    on_modified_line: Mapped[bool] = mapped_column(Boolean, default=False)
    introduced_by_pr: Mapped[bool] = mapped_column(Boolean, default=False)
    source_sink: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ─────────────── v0 attack surface: observations, changes, exposures ───────────────
#
# An observation is "what a collector or importer saw at a moment", with the
# coverage it had. A change is a comparison between two observations of equal
# coverage: a failed collection never becomes "port closed" or "host gone".
# An exposure event is the condition someone has to decide about; it has a
# stable identity so repeated observations do not duplicate it.

# Every kind the runner can emit. A missing one is not a cosmetic bug: the upload
# is rejected with 422, the run is never closed, and the job sits `leased` until
# its lease expires — from the console, a hang with no error.
OBSERVATION_KINDS = {"host", "port", "dns", "certificate", "technology", "web_path",
                     "web_paths", "misconfig", "sast", "sbom", "secrets"}
OBSERVATION_COVERAGES = {"full", "partial", "failed"}
EXPOSURE_STATES = {"open", "accepted", "resolved", "false_positive"}
REOPEN_POLICIES = {"on_new_observation", "manual"}


class Observation(Base):
    __tablename__ = "observations"
    __table_args__ = (
        Index("ix_observations_asset_kind", "asset_id", "kind", "observed_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), index=True)
    asset_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("assets.id"), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(24))
    subject: Mapped[str] = mapped_column(String(1024))
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)
    source: Mapped[str] = mapped_column(String(64), default="import")
    coverage: Mapped[str] = mapped_column(String(16), default="full")
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ExposureEvent(Base, TimestampMixin):
    """A condition that needs a decision, deduped by a stable identity."""

    __tablename__ = "exposure_events"
    __table_args__ = (UniqueConstraint("org_id", "stable_key", name="uq_exposure_key"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), index=True)
    asset_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("assets.id"), nullable=True, index=True)
    stable_key: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(24), index=True)
    title: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    state: Mapped[str] = mapped_column(String(24), default="open", index=True)
    decision_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    accepted_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    reopen_policy: Mapped[str] = mapped_column(String(32), default="on_new_observation")
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)


class ExposureDecision(Base):
    __tablename__ = "exposure_decisions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    event_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("exposure_events.id", ondelete="CASCADE"), index=True)
    action: Mapped[str] = mapped_column(String(24))
    from_state: Mapped[str | None] = mapped_column(String(24), nullable=True)
    to_state: Mapped[str] = mapped_column(String(24))
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    valid_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ─────────────── v0 attack surface: web endpoints, lookalikes ───────────────
#
# A path returning HTTP 200 is an observation, not a vulnerability. States are
# explicit so the screen can distinguish a candidate, an observed response, a
# confirmed finding and something nobody evaluated (excluded).

WEB_ENDPOINT_STATES = {"candidate", "observed", "confirmed_finding",
                       "excluded", "not_evaluated"}
LOOKALIKE_STATES = {"candidate", "confirmed", "external", "dismissed"}
LOOKALIKE_SIMILARITY = {"typosquat", "homoglyph", "tld_swap", "subdomain",
                        "combosquatting", "bitsquatting", "other"}


class WebEndpoint(Base, TimestampMixin):
    __tablename__ = "web_endpoints"
    __table_args__ = (
        UniqueConstraint("org_id", "origin", "path", "method",
                         name="uq_web_endpoint_identity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), index=True)
    asset_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("assets.id"), nullable=True, index=True)
    origin: Mapped[str] = mapped_column(String(512), index=True)
    path: Mapped[str] = mapped_column(String(1024))
    method: Mapped[str] = mapped_column(String(16), default="GET")
    state: Mapped[str] = mapped_column(String(24), default="candidate", index=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    discovery_source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow)
    finding_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("findings.id"), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class LookalikeDomain(Base, TimestampMixin):
    """A watched root domain or a candidate impersonating it.

    Candidates are **external observed resources**: nothing here authorizes
    active testing, and DNS resolving is not proof of registration or malice.
    """

    __tablename__ = "lookalike_domains"
    __table_args__ = (
        UniqueConstraint("org_id", "root_domain", "candidate",
                         name="uq_lookalike_identity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), index=True)
    root_domain: Mapped[str] = mapped_column(String(255), index=True)
    candidate: Mapped[str] = mapped_column(String(255), index=True)
    similarity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    state: Mapped[str] = mapped_column(String(24), default="candidate", index=True)
    registration_evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    dns: Mapped[dict] = mapped_column(JSON, default=dict)
    mx: Mapped[dict] = mapped_column(JSON, default=dict)
    certificates: Mapped[dict] = mapped_column(JSON, default=dict)
    registration_state: Mapped[str] = mapped_column(String(24), default="unknown")
    review_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ─────────────── v0 cycles and work management ───────────────
#
# A cycle is a time-boxed evaluation with a charter and a frozen reference.
# Activating it snapshots the charter and the membership: changing a group later
# never rewrites what the cycle was looking at. A cycle grants no authorization.

CYCLE_STATES = {"planning", "active", "review", "closed"}
# What kind of exercise this window is. The kind is not decoration: it decides who
# produces the evidence (a tool, a pentest team, a supply-chain review), what the
# review is judged on, and how the KPI is bucketed. `sweep` is the estate-wide
# baseline, `campaign` is one technique family against one subset.
CYCLE_KINDS = {"sweep", "campaign", "pentest_external", "pentest_internal",
               "supply_chain", "ai_redteam"}
WORK_ITEM_KINDS = {"task", "request", "review", "acceptance"}
WORK_ITEM_STATUSES = {"open", "in_progress", "awaiting_review", "approved",
                      "rejected", "withdrawn", "done"}


class Cycle(Base):
    __tablename__ = "cycles"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_cycle_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    # The campaign's working note: what the client said, what we promised, what the
    # scope letter excluded. Free text, kept with the cycle it belongs to.
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # sweep | campaign | pentest_external | pentest_internal | supply_chain |
    # ai_redteam. Set at creation, never changed by activation: the kind is what a
    # KPI is bucketed by, so rewriting it later would rewrite history.
    kind: Mapped[str] = mapped_column(String(24), default="sweep", index=True)
    state: Mapped[str] = mapped_column(String(16), default="planning", index=True)
    starts_on: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    ends_on: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    charter: Mapped[dict] = mapped_column(JSON, default=dict)
    selection: Mapped[dict] = mapped_column(JSON, default=dict)
    snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    snapshot_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    activated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    review: Mapped[dict] = mapped_column(JSON, default=dict)
    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CycleDocument(Base):
    """One file that belongs to the campaign: the scope letter, the pentest report.

    The bytes are kept rather than linked, because the review is written from the
    document and a URL that rots takes the evidence with it.
    """

    __tablename__ = "cycle_documents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), index=True)
    cycle_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cycles.id", ondelete="CASCADE"), index=True)
    filename: Mapped[str] = mapped_column(String(512))
    media_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    size: Mapped[int] = mapped_column(Integer, default=0)
    data: Mapped[bytes] = mapped_column(LargeBinary)
    uploaded_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CycleMembership(Base):
    """Frozen initial reference: one row per resource the cycle was opened on."""

    __tablename__ = "cycle_memberships"
    __table_args__ = (
        UniqueConstraint("cycle_id", "entity_type", "entity_id",
                         name="uq_cycle_membership"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    cycle_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cycles.id", ondelete="CASCADE"), index=True)
    entity_type: Mapped[str] = mapped_column(String(24))
    entity_id: Mapped[str] = mapped_column(String(36))
    label: Mapped[str | None] = mapped_column(String(512), nullable=True)
    included_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    removed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)


class CycleFinding(Base):
    __tablename__ = "cycle_findings"
    __table_args__ = (UniqueConstraint("cycle_id", "finding_id", name="uq_cycle_finding"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    cycle_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("cycles.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id"))
    linked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    source: Mapped[str] = mapped_column(String(16), default="manual")


class AttackTechnique(Base):
    """One MITRE ATT&CK technique the catalogue knows about.

    `capability` is the platform capability that could test it, or NULL when nothing
    we run today can reach it (phishing, DoS, exfiltration). A technique nobody can
    test is listed and counted, never scored as covered.
    """

    __tablename__ = "attack_techniques"

    id: Mapped[str] = mapped_column(String(24), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    tactic: Mapped[str] = mapped_column(String(64), index=True)
    capability: Mapped[str | None] = mapped_column(String(32), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


class ThreatEntry(Base):
    """One technique declared against one crown jewel, and why it applies."""

    __tablename__ = "threat_entries"
    __table_args__ = (UniqueConstraint("component_id", "technique_id",
                                       name="uq_threat_entry_component_technique"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), index=True)
    component_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("application_components.id"), index=True)
    technique_id: Mapped[str] = mapped_column(
        String(24), ForeignKey("attack_techniques.id"))
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    added_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AttackerProfile(Base):
    """A reusable bundle of techniques — "opportunistic external", "supply chain".

    Org-scoped, not per cycle: an attacker profile outlives any single window, and a
    cycle cites it instead of redefining it.
    """

    __tablename__ = "attacker_profiles"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_attacker_profile_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    techniques: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list of ids
    # Who authored the profile: `custom` (written here), `external` (came from a
    # report or a public actor description), `none` (unknown provenance, said out
    # loud instead of pretending it is ours).
    origin: Mapped[str] = mapped_column(String(16), default="custom")
    # Tooling the actor is known for (nmap, metasploit, commodity). Free text on
    # purpose: a tool missing from every catalogue still describes the actor.
    tools: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class WorkItem(Base, TimestampMixin):
    """A task, a request for a decision, or an acceptance with a validity.

    Assignments and findings keep their own identity; this row is the work the
    queues read, never a duplicate of the finding.
    """

    __tablename__ = "work_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), index=True)
    kind: Mapped[str] = mapped_column(String(16), default="task", index=True)
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="open", index=True)
    assignee: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    requested_by: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    reviewer: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    due_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    valid_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    decision_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    remind_count: Mapped[int] = mapped_column(Integer, default=0)
    last_reminded_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    cycle_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("cycles.id"), nullable=True)
    finding_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("findings.id"), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OrganizationInvitation(Base, TimestampMixin):
    """A pending seat: the email is the identity until the invite is accepted.

    The raw token is shown once to whoever sent the invitation and stored only
    as a SHA-256 hash, exactly like a session. Repeating an invitation for the
    same address reuses the row and rotates the token, so the table never shows
    two live links for one person.
    """

    __tablename__ = "org_invitations"
    __table_args__ = (
        UniqueConstraint("org_id", "email", name="uq_org_invitations_email"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    email: Mapped[str] = mapped_column(String(320))
    # Same vocabulary as users.role (`viewer`/`analyst`/`admin`); the console
    # renders those as Viewer / Member / Administrator.
    role: Mapped[str] = mapped_column(String(16), default="analyst")
    team_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("teams.id"), nullable=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    invited_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    accepted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    last_sent_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    last_delivery: Mapped[str | None] = mapped_column(String(255), nullable=True)


class Team(Base, TimestampMixin):
    """Optional grouping that scopes what a member can see.

    A team grants reach over its assets and findings; a member with no team and
    no organization-wide visibility therefore sees nothing. Teams never widen a
    role — a viewer in a team is still a viewer.
    """

    __tablename__ = "teams"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_teams_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(320), nullable=True)


class TeamMember(Base):
    """Team ↔ user N:M. A pending invitation joins the team on acceptance."""

    __tablename__ = "team_members"
    __table_args__ = (
        UniqueConstraint("team_id", "user_id", name="uq_team_members_pair"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    team_id: Mapped[str] = mapped_column(String(36), ForeignKey("teams.id"), index=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), index=True)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    added_by: Mapped[str | None] = mapped_column(String(320), nullable=True)


class IntegrationConnection(Base, TimestampMixin):
    """One outbound connection (code host or ticket tracker) owned by an org.

    `kind` separates the two onboarding surfaces — "scm" (list/clone/analyse,
    never push) and "tickets" (import/export). The credential is encrypted with
    the platform key before it reaches this table and is never returned by the
    API: `_connection_data` exposes only the account, provider and status.
    """

    __tablename__ = "integration_connections"
    __table_args__ = (
        UniqueConstraint("org_id", "kind", "provider", "base_url",
                         name="uq_integration_connections_target"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    kind: Mapped[str] = mapped_column(String(16), default="scm")
    provider: Mapped[str] = mapped_column(String(32), default="github")
    label: Mapped[str | None] = mapped_column(String(128), nullable=True)
    base_url: Mapped[str] = mapped_column(String(255), default="")
    account: Mapped[str | None] = mapped_column(String(255), nullable=True)
    secret_cipher: Mapped[str] = mapped_column(Text)
    # Provider-specific non-secret extras (Jira project key, default branch…).
    config: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Declared by the operator and enforced by us: no connection is ever used
    # to write. Kept as a column so a future read/write mode must be explicit.
    access: Mapped[str] = mapped_column(String(16), default="read")
    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(320), nullable=True)


class PlatformSecret(Base):
    """Key material that has to live somewhere when the env does not provide it.

    Production sets PLATFORM_SECRET_KEY so the key never shares storage with the
    data it protects; a fresh installation without it gets a generated key here
    and the onboarding mail status says so.
    """

    __tablename__ = "platform_secrets"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PlatformSetting(Base):
    """Deployment-wide configuration that an operator can change at runtime.

    Currently one row: `smtp`. The non-secret fields live as JSON in `value`;
    a password, when there is one, is sealed with the platform key exactly like
    an integration credential. Environment variables remain the fallback — a
    stored row, once written, is explicit and wins.
    """

    __tablename__ = "platform_settings"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="{}")
    secret_cipher: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    updated_by: Mapped[str | None] = mapped_column(String(320), nullable=True)


class InternalRun(Base, TimestampMixin):
    """One execution of a job the platform runs itself.

    `scan_jobs` is work handed to a worker; the advisory clock runs inside the
    platform and still needs a record somebody can read afterwards: what it did,
    how long it took, and why it failed. Without this the console could only say
    "it ran" — and "it ran" is not evidence.
    """

    __tablename__ = "internal_runs"
    __table_args__ = (Index("ix_internal_runs_org_name", "org_id", "name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), index=True)
    # What ran: `advisory-clock` today, and the key the console lists by.
    name: Mapped[str] = mapped_column(String(64), default="advisory-clock")
    # Why it ran: `schedule` (the clock woke up) or `manual` (somebody pressed it).
    trigger: Mapped[str] = mapped_column(String(16), default="schedule")
    status: Mapped[str] = mapped_column(String(16), default="running")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    counters: Mapped[str] = mapped_column(Text, default="{}")
    log: Mapped[str] = mapped_column(Text, default="")
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)

class ComponentRepository(Base):
    """Component ↔ repository edge. A repository can back several components
    (a monorepo), and a component can be built from several repositories."""

    __tablename__ = "component_repositories"
    __table_args__ = (
        UniqueConstraint("component_id", "repository_id",
                         name="uq_component_repository"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    component_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("application_components.id"), index=True)
    repository_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("repositories.id"), index=True)
    relation: Mapped[str] = mapped_column(String(32), default="code")
    added_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    removed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)


class HealthProbe(Base):
    """Optional, read-only version check for one deployment.

    The endpoint is a GET (never a write to the target), so a probe can run on a
    schedule without any authorization grant. The token is sealed like every
    other credential and never returned.
    """

    __tablename__ = "health_probes"
    __table_args__ = (UniqueConstraint("deployment_id", name="uq_health_probe_deployment"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    deployment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("deployments.id"), index=True)
    url: Mapped[str] = mapped_column(String(1024))
    token_cipher: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Dotted paths into the JSON body; "auto" searches the usual version keys.
    version_path: Mapped[str] = mapped_column(String(128), default="auto")
    status_path: Mapped[str] = mapped_column(String(128), default="status")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    interval_minutes: Mapped[int] = mapped_column(Integer, default=0)
    last_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    last_ok_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ─────────────── v01 scan flows: the timeline ───────────────


class ScanEvent(Base):
    """One line of a scan flow's timeline: append-only, never edited.

    `status` on the job is a projection of these rows; that projection is what
    makes "it was abandoned and then answered" representable at all. `seq` is
    assigned by the platform, `at_server` is when the platform saw the event and
    `at_client` is when the executor claims it happened — client clocks are
    evidence, never ordering.
    """

    __tablename__ = "scan_events"
    __table_args__ = (
        UniqueConstraint("job_id", "seq", name="uq_scan_event_seq"),
        Index("ix_scan_events_job", "job_id", "seq"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), index=True)
    job_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"))
    seq: Mapped[int] = mapped_column(Integer)
    kind: Mapped[str] = mapped_column(String(32))
    source: Mapped[str] = mapped_column(String(16), default="platform")
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    at_server: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow)
    at_client: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    detail: Mapped[str] = mapped_column(Text, default="{}")


# ─────────────── AI harness (F1): providers, budget, runs ───────────────
#
# Deployment-wide configuration (D17): one provider list and one budget, because
# this is an internal operator tool (D16). Runs and steps still carry `org_id`,
# because the *question* is about one estate even when the configuration is not.
#
# The provider key is sealed with the platform key (`secrets.seal`) and is never
# returned by the API: `_provider_data` exposes `key_set`, not the cipher (D9).

AI_PROVIDER_KINDS = {"openai-compatible", "anthropic"}

AI_RUN_STATUSES = {"running", "answered", "failed", "stopped_budget",
                   "stopped_max_steps", "stopped_no_provider", "stopped_no_progress"}

# ── The triage queue (F3, D29–D30) ─────────────────────────────────────────
#: Who found it.
FINDING_ORIGINS = {"scanner", "pentest-external", "pentest-internal",
                   "shauron-ai", "manual"}
#: A human verdict. The agent may only create `new`.
TRIAGE_STATUSES = {"new", "triaged", "rejected", "duplicate", "accepted"}
#: Proof, independent of impact.
EVIDENCE_LEVELS = {"hypothesis", "static", "observed", "demonstrated"}
#: Impact, independent of proof.
EXPLOIT_STATES = {"none", "attempted", "reproduced", "effect_proven"}
#: Counted toward severity and risk: a person looked, and it is not a guess.
COUNTED_TRIAGE = {"triaged", "accepted"}


class AiProvider(Base, TimestampMixin):
    """One model endpoint. `kind` picks the wire format, never the capability."""

    __tablename__ = "ai_providers"
    __table_args__ = (UniqueConstraint("name", name="uq_ai_provider_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    name: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(32), default="openai-compatible")
    base_url: Mapped[str] = mapped_column(String(255), default="")
    model: Mapped[str] = mapped_column(String(128), default="")
    secret_cipher: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Price per million tokens. NULL means "unknown": the ledger then counts tokens
    # and says the price is unknown, instead of inventing a cost (D10).
    price_in: Mapped[float | None] = mapped_column(Float, nullable=True)
    price_out: Mapped[float | None] = mapped_column(Float, nullable=True)
    max_output_tokens: Mapped[int] = mapped_column(Integer, default=1024)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    # Same reason as chat_sessions: the column is NOT NULL in the migration, so the
    # model has to write it or the first provider the operator saves is a 500.
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow)


class AiSettings(Base):
    """Exactly one row (`id='default'`): the ceiling the operator can predict."""

    __tablename__ = "ai_settings"

    id: Mapped[str] = mapped_column(String(16), primary_key=True, default="default")
    monthly_token_cap: Mapped[int | None] = mapped_column(Integer, nullable=True)
    monthly_cost_cap: Mapped[float | None] = mapped_column(Float, nullable=True)
    # A lookup costs one call; the F2 chain costs about seven. The cap is the
    # investigation ceiling, not the lookup one: a cap that truncates every CVE
    # question is a cap that teaches the operator to raise it.
    max_steps: Mapped[int] = mapped_column(Integer, default=12)
    max_specialists: Mapped[int] = mapped_column(Integer, default=6)
    redteam_allowed: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    updated_by: Mapped[str | None] = mapped_column(String(320), nullable=True)


class AiRun(Base):
    """One question, its plan, its budget and how it ended.

    Written `running` **before** the slow work and closed after: a run you cannot
    see while it runs is indistinguishable from one that never started (the
    `InternalRun` lesson).
    """

    __tablename__ = "ai_runs"
    __table_args__ = (Index("ix_ai_runs_org_started", "org_id", "started_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), index=True)
    #: The conversation this run belongs to (A6). A run without one is a question
    #: asked outside the channel; with it, the channel shows who delegated what
    #: without keeping a second store of its own.
    session_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("chat_sessions.id"), nullable=True, index=True)
    actor: Mapped[str] = mapped_column(String(255), default="system")
    # The role the caller held when the run started (D44): every tool call of this
    # run is authorized as this role, never as the machine that owns the process.
    actor_role: Mapped[str] = mapped_column(String(16), default="viewer")
    question: Mapped[str] = mapped_column(Text)
    mode: Mapped[str] = mapped_column(String(16), default="ask")
    status: Mapped[str] = mapped_column(String(24), default="running", index=True)
    stop_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    provider_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("ai_providers.id"), nullable=True)
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    answer: Mapped[str | None] = mapped_column(Text, nullable=True)
    steps: Mapped[int] = mapped_column(Integer, default=0)
    #: Optional ceiling for this run alone. NULL means the monthly cap is the only
    #: bound: a per-run cap that is too tight cuts context, not waste.
    token_budget: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tool_calls: Mapped[int] = mapped_column(Integer, default=0)
    tokens_in: Mapped[int] = mapped_column(Integer, default=0)
    tokens_out: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float | None] = mapped_column(Float, nullable=True)
    price_known: Mapped[bool] = mapped_column(Boolean, default=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)


class AiStep(Base):
    """One model call: what it was asked, what it called, what it cost."""

    __tablename__ = "ai_steps"
    __table_args__ = (UniqueConstraint("run_id", "seq", name="uq_ai_step_seq"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("ai_runs.id", ondelete="CASCADE"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    role: Mapped[str] = mapped_column(String(32), default="orchestrator")
    prompt_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Tool calls as `[{tool, args, status, result_digest}]` — the digest, not the
    # payload: the payload lives in the tool's own tables and would double the row.
    tool_calls: Mapped[str] = mapped_column(Text, default="[]")
    handoff: Mapped[str | None] = mapped_column(Text, nullable=True)
    tokens_in: Mapped[int] = mapped_column(Integer, default=0)
    tokens_out: Mapped[int] = mapped_column(Integer, default=0)
    #: Prompt tokens the provider served from its cache; zero when the provider is
    #: silent about it, which is itself information (no cache savings on this plan).
    cached_tokens: Mapped[int] = mapped_column(Integer, default=0)
    #: The provider's own `usage` block, verbatim. Some endpoints report what a token
    #: count cannot express (a flat plan's remaining allowance, a metered unit), and
    #: recording it before knowing its shape is the difference between a measurement
    #: and a guess. Interpretation happens later, in `month_spend`.
    usage_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    cost_usd: Mapped[float | None] = mapped_column(Float, nullable=True)
    # Which run and phase produced this step. `price_known` (above) is what makes an
    # unpriced call visible; a missing usage must never be recorded as "$0".
    parent_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    phase: Mapped[str | None] = mapped_column(String(48), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow)


class AiPrompt(Base):
    """One version of one participant's instructions (A8).

    The code string in `ai/specialists.py` is the **floor**: it seeds v1 and answers
    whenever no row exists, so a fresh database, the test suite and a rollback all work
    with zero rows. A row only ever *overrides*, and only one row per key is `active` at
    a time — which is what lets a step say `intel.cve@3` and mean it.

    Promotion is a human act (`activated_by/at`), and a model may write a `draft` but
    never activate one. That is D24 after its revision: the ban is on self-activation,
    not on authoring.
    """

    __tablename__ = "ai_prompts"
    __table_args__ = (UniqueConstraint("key", "version", name="uq_ai_prompt_version"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    #: The specialist name, or `field.generic` for the loop inside Shauron.
    key: Mapped[str] = mapped_column(String(64), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    body: Mapped[str] = mapped_column(Text)
    #: draft | active | archived. Exactly one `active` per key, enforced in code.
    status: Mapped[str] = mapped_column(String(16), default="draft", index=True)
    #: Why this version exists. A version without a reason is a mystery in a month.
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    activated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    activated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow)


AI_PROMPT_STATUSES = {"draft", "active", "archived"}


# ─────────────── chat sessions (F1): the record, and what a prompt sees ───────────────
#
# Two different things share these rows and must never be confused (D67):
#   * `chat_turns` is the RECORD — every message verbatim, nothing ever removed;
#   * the PROMPT is assembled per turn from `brief + pins + last K turns` (D68).
# Compression therefore cannot lose history: it changes what the model sees, never
# what the operator can read.

CHAT_TURN_ROLES = {"user", "orchestrator", "specialist", "compaction"}


class ChatSession(Base, TimestampMixin):
    """One conversation: many turns, many runs, one subject."""

    __tablename__ = "chat_sessions"
    __table_args__ = (Index("ix_chat_sessions_org_turn", "org_id", "last_turn_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), index=True)
    created_by: Mapped[str] = mapped_column(String(320), default="system")
    title: Mapped[str] = mapped_column(String(255), default="")
    subject_kind: Mapped[str | None] = mapped_column(String(32), nullable=True)
    subject_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    profile_key: Mapped[str] = mapped_column(String(32), default="palantir")
    status: Mapped[str] = mapped_column(String(16), default="idle", index=True)
    # The rolling brief: what compression produced, versioned so a metric shift can
    # be attributed to the compaction that caused it.
    brief: Mapped[str | None] = mapped_column(Text, nullable=True)
    brief_version: Mapped[int] = mapped_column(Integer, default=0)
    brief_tokens: Mapped[int] = mapped_column(Integer, default=0)
    last_turn_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    archived_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    # The migration makes this NOT NULL: a row that can be archived and retitled has
    # an update time, and the model owes it a value or every insert fails.
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow)


class ChatTurn(Base):
    """One message. The record: never deleted, never rewritten."""

    __tablename__ = "chat_turns"
    __table_args__ = (UniqueConstraint("session_id", "seq", name="uq_chat_turn_seq"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("chat_sessions.id", ondelete="CASCADE"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    role: Mapped[str] = mapped_column(String(16))
    author: Mapped[str | None] = mapped_column(String(320), nullable=True)
    profile_key: Mapped[str | None] = mapped_column(String(32), nullable=True)
    content: Mapped[str] = mapped_column(Text)
    citations: Mapped[str] = mapped_column(Text, default="[]")
    #: The buttons this answer offered, validated against the estate
    #: (`ai/suggestions.py`). Stored with the turn, not in the UI: a replayed answer has
    #: to bring back the affordance it had.
    suggestions: Mapped[str] = mapped_column(Text, default="[]")
    run_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("ai_runs.id"), nullable=True)
    tokens: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow)


class ChatPin(Base):
    """A user's override: this survives compression, whatever the window says."""

    __tablename__ = "chat_pins"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("chat_sessions.id", ondelete="CASCADE"), index=True)
    turn_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("chat_turns.id", ondelete="CASCADE"), nullable=True)
    note: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow)


# ─────────────────── F4: the field runtime (D25–D28, D31–D35) ──────────────────
#
# A mission is the operator's authorization; a task is one contract; a field agent
# is a task's execution inside Shauron. The platform owns the envelope, the budget
# and the scope — never an individual tool invocation.

AGENT_CAPABILITIES = {"validate", "discover", "exploit"}
#: A mission names the profile that authorized it (D42). Palantír never gets one:
#: it answers from what the estate knows and has no field lane.
AGENT_PROFILES = {"angmar", "morgoth"}
AGENT_MISSION_STATUSES = {"draft", "approved", "running", "done", "failed", "revoked"}
AGENT_TASK_STATUSES = {"queued", "claimed", "running", "done", "failed", "expired"}
AGENT_TASK_KINDS = {"validate.finding", "recon.surface", "exploit.chain",
                    "probe.sibling"}
AGENT_EVENT_KINDS = {"tool", "observation", "note", "refusal", "final"}
#: The only two paths a task token opens (D60). Anything else is an API key's job.
AGENT_TOKEN_PATHS = ("/api/v1/agent/llm/complete",
                     "/api/v1/agent/tasks/",
                     "/api/v1/agent/scope/check")


class AgentMission(Base, TimestampMixin):
    """One authorization: what may be touched, with what tools, under what ceiling."""

    __tablename__ = "agent_missions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id"), index=True)
    actor: Mapped[str] = mapped_column(String(255), default="system")
    actor_role: Mapped[str] = mapped_column(String(16), default="viewer")
    goal: Mapped[str] = mapped_column(Text)
    capability: Mapped[str] = mapped_column(String(16))
    #: Which profile authorized it (D42). The lane and the capability must agree:
    #: Angmar validates, Morgoth discovers and exploits.
    profile: Mapped[str] = mapped_column(String(16), default="angmar", index=True)
    # 32, not 16: `awaiting_approval` is 17 and the gate must be nameable.
    status: Mapped[str] = mapped_column(String(32), default="draft", index=True)
    #: JSON list of {kind, value, methods, rate_per_min}
    targets: Mapped[str] = mapped_column(Text, default="[]")
    #: JSON list of tool names — an allowlist, not a suggestion
    tools: Mapped[str] = mapped_column(Text, default="[]")
    grant_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    grant_level: Mapped[str | None] = mapped_column(String(16), nullable=True)
    #: JSON {steps, tokens, wall_s, usd}
    budget: Mapped[str] = mapped_column(Text, default="{}")
    evidence: Mapped[str] = mapped_column(Text, default="{}")
    deadline_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    run_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("ai_runs.id"), nullable=True)
    signature: Mapped[str | None] = mapped_column(String(200), nullable=True)
    # The gate: a mission starts `awaiting_approval`, and these two columns are the
    # human act that let it run. Neither is a default — a script cannot approve.
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)


class AgentTask(Base, TimestampMixin):
    """One contract small enough to finish: `{kind, target, tools, must_return}`."""

    __tablename__ = "agent_tasks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    mission_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("agent_missions.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    # A task spawned by another task is how a field subagent exists: the parent keeps
    # its envelope, the child gets its own token and budget.
    parent_task_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    target: Mapped[str] = mapped_column(Text, default="{}")
    tools: Mapped[str] = mapped_column(Text, default="[]")
    must_return: Mapped[str] = mapped_column(Text, default="[]")
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    worker: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    #: Hash of the task token issued at claim time; never the token itself.
    token_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True, unique=True, index=True)
    token_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True)


class AgentTaskEvent(Base):
    """What the field agent did, as it did it (D61: the log is not the record)."""

    __tablename__ = "agent_task_events"
    __table_args__ = (UniqueConstraint("task_id", "seq", name="uq_agent_event_seq"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    task_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("agent_tasks.id", ondelete="CASCADE"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    kind: Mapped[str] = mapped_column(String(16))
    tool: Mapped[str | None] = mapped_column(String(64), nullable=True)
    payload: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow)


class AgentSpec(Base):
    """One agent in the catalogue: identity, the tools it may use, its contract.

    Deployment-wide, like `ai_providers` — the harness is one per deployment. `draft`
    means declared but not usable: `validate.finding` was seeded that way because the
    field tools it names do not exist yet, and the console has to say so rather than
    offering a button that cannot work.
    """

    __tablename__ = "agent_specs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    name: Mapped[str] = mapped_column(String(64))
    slug: Mapped[str] = mapped_column(String(64), unique=True)
    #: `class` is a Python keyword: the column keeps the domain word, the attribute
    #: does not. `orchestrator | analyst | query | field`.
    agent_class: Mapped[str] = mapped_column(String(24), default="analyst")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    avatar: Mapped[str | None] = mapped_column(String(8), nullable=True)
    color: Mapped[str | None] = mapped_column(String(16), nullable=True)
    tools: Mapped[str] = mapped_column(Text, default="[]")
    must_return: Mapped[str] = mapped_column(Text, default="[]")
    tech_affinity: Mapped[str] = mapped_column(Text, default="[]")
    # An agent is a node in a tree, not a flat list: `parent_slug` names whose child it
    # is, `allowed_tools` narrows what it may call. NULL = inherit, [] = none.
    parent_slug: Mapped[str | None] = mapped_column(String(64), nullable=True)
    allowed_tools: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="draft", index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow)


class AgentEvent(Base):
    """One line of a thread: who said it, of what kind, and what it points at.

    The thread is a projection of these rows, never a document the UI keeps. A
    `thread` is `chat:<session_id>` or `mission:<id>`; the author is either a spec
    slug or the operator, and `refs` carries the ids the line is about.
    """

    __tablename__ = "agent_events"
    __table_args__ = (Index("ix_agent_events_thread_seq", "thread", "seq"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"),
                                        index=True)
    thread: Mapped[str] = mapped_column(String(80))
    seq: Mapped[int] = mapped_column(Integer)
    author_spec: Mapped[str | None] = mapped_column(String(64), nullable=True)
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    kind: Mapped[str] = mapped_column(String(24), default="message")
    body: Mapped[str | None] = mapped_column(Text, nullable=True)
    refs: Mapped[str] = mapped_column(Text, default="[]")
    # Which execution this line belongs to, and which line it answers. Together they
    # turn the thread into a directed graph: `run_ref` groups a family, `reply_to`
    # draws the edge — without either, the UI can only render a flat log.
    run_ref: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    reply_to: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow)


class AgentRun(Base, TimestampMixin):
    """One agent execution — the unit of state, budget and attribution.

    A chat turn can own one, a mission can own many, and a subagent is a row with
    `parent_run_id` set. The `thread` it writes to is the mission's or the chat's, so
    the UI never has to guess where a run belongs.
    """

    __tablename__ = "agent_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"),
                                        index=True)
    mission_id: Mapped[str | None] = mapped_column(String(36), index=True)
    parent_run_id: Mapped[str | None] = mapped_column(String(36), index=True)
    spec_slug: Mapped[str] = mapped_column(String(64))
    thread: Mapped[str | None] = mapped_column(String(96), index=True)
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    goal: Mapped[str | None] = mapped_column(Text, nullable=True)
    max_turns: Mapped[int | None] = mapped_column(Integer, nullable=True)
    turn_count: Mapped[int] = mapped_column(Integer, default=0)
    cost_ceiling_usd: Mapped[float | None] = mapped_column(Float, nullable=True)
    cost_usd: Mapped[float] = mapped_column(Float, default=0)
    tokens_in: Mapped[int] = mapped_column(Integer, default=0)
    tokens_out: Mapped[int] = mapped_column(Integer, default=0)
    engine_task_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    blocked_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True),
                                                        nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True),
                                                      nullable=True)


class AgentMessage(Base):
    """A line with a recipient — the non-linear part of the thread.

    `to_run` names the addressee, `to_spec` names a role when the run does not exist
    yet, `reply_to` points at the line being answered. A message carries text and
    nothing else: it can never widen scope, approve a tool or change a budget.
    """

    __tablename__ = "agent_messages"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"),
                                        index=True)
    mission_id: Mapped[str | None] = mapped_column(String(36), index=True)
    from_run: Mapped[str | None] = mapped_column(String(36), nullable=True)
    to_run: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    to_spec: Mapped[str | None] = mapped_column(String(64), nullable=True)
    kind: Mapped[str] = mapped_column(String(24), default="message")
    body: Mapped[str] = mapped_column(Text)
    reply_to: Mapped[str | None] = mapped_column(String(36), nullable=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True),
                                                          nullable=True)
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True),
                                                     nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AgentArtifact(Base):
    """Bytes an agent produced or consumed, with a hash.

    Metadata only; the body lives wherever `storage` points, and `sha256` makes the row
    verifiable. This is what answers "how did the data move": who produced it, under
    which task, and which run read it.
    """

    __tablename__ = "agent_artifacts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"),
                                        index=True)
    mission_id: Mapped[str | None] = mapped_column(String(36), index=True)
    run_id: Mapped[str | None] = mapped_column(String(36), index=True)
    task_id: Mapped[str | None] = mapped_column(String(36), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    bytes: Mapped[int] = mapped_column(Integer, default=0)
    storage: Mapped[str | None] = mapped_column(String(255), nullable=True)
    meta: Mapped[str | None] = mapped_column(Text, nullable=True)
    produced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Candidate(Base, TimestampMixin):
    """What an agent proposes. Never a finding — a finding needs a gate chain."""

    __tablename__ = "candidates"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"),
                                        index=True)
    mission_id: Mapped[str | None] = mapped_column(String(36), index=True)
    run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    finding_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    title: Mapped[str] = mapped_column(Text)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    claim: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    state: Mapped[str] = mapped_column(String(24), default="proposed", index=True)


class GateRun(Base):
    """One stage's verdict on one candidate, with the reason it gave."""

    __tablename__ = "gate_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"),
                                        index=True)
    candidate_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("candidates.id", ondelete="CASCADE"), index=True)
    stage: Mapped[str] = mapped_column(String(48))
    verdict: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_ref: Mapped[str | None] = mapped_column(String(120), nullable=True)
    cost_usd: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GrantIdentity(Base):
    """A principal the grant allows us to be, sealed.

    Two of these are what turn "the code does not check ownership" into "user B received
    user A's record". The credential is sealed with `secrets.seal` and never leaves the
    row: `headers_cipher` is opened in memory, used for one request, and discarded.
    """

    __tablename__ = "grant_identities"
    __table_args__ = (UniqueConstraint("grant_id", "label", name="uq_grant_identity_label"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_hex)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"),
                                        index=True)
    grant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_grants.id", ondelete="CASCADE"), index=True)
    label: Mapped[str] = mapped_column(String(64))
    headers_cipher: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True),
                                                          nullable=True)

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
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

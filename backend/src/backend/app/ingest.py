"""CycloneDX SBOM ingestion: normalize a document into components + version links.

Identity: a component is keyed by `purl` when present, otherwise by its
`bom-ref`. The dependency graph decides `is_direct` (children of the SBOM's
metadata component) and `parent_purl` (the purl of the parent bom-ref). Trivy
manifest provenance is picked up from any property whose name contains
`SrcFile`.
"""
import hashlib
import json

from backend.app import models


class SbomDocumentError(ValueError):
    """Raised when the payload is not a workable CycloneDX document."""


REQUIRED_KEYS = {"name"}


def identity_key(purl: str | None, name: str | None, version: str | None) -> str:
    """Stable identity recipe for dedup across re-scans.

    Trivy mints a random `bom-ref` per run for purl-less components (e.g. the
    manifest pseudo-component), so bom-ref identity would duplicate on every
    scan. Purl-less identity therefore keys on name+version, mirroring the
    reference platform's per-kind fingerprint recipes.
    """
    if purl:
        return purl
    if name:
        digest = hashlib.sha256(f"nonpurl:{name}:{version or ''}".encode("utf-8")).hexdigest()
        return f"nonpurl:{digest}"
    raise SbomDocumentError("component missing both purl and name")


def _property_strings(component: dict) -> str | None:
    for prop in component.get("properties") or []:
        if isinstance(prop, dict):
            name = str(prop.get("name", ""))
            if "srcfile" in name.lower():
                value = prop.get("value")
                if isinstance(value, str) and value:
                    return value
    return None


def _license_of(component: dict) -> str | None:
    licenses = component.get("licenses") or []
    for entry in licenses:
        if isinstance(entry, dict):
            if isinstance(entry.get("expression"), str) and entry["expression"]:
                return entry["expression"]
            license_block = entry.get("license")
            if isinstance(license_block, dict):
                for key in ("id", "name"):
                    value = license_block.get(key)
                    if isinstance(value, str) and value:
                        return value
    return None


def parse(document: dict) -> dict:
    """Validate and normalize; raises SbomDocumentError on unusable input."""
    if not isinstance(document, dict):
        raise SbomDocumentError("document must be a JSON object")
    if document.get("bomFormat") != "CycloneDX":
        raise SbomDocumentError("bomFormat must be CycloneDX")
    spec = document.get("specVersion")
    if not isinstance(spec, str) or not spec.startswith("1."):
        raise SbomDocumentError("specVersion must be a CycloneDX 1.x version")
    metadata = document.get("metadata") or {}
    root = metadata.get("component") if isinstance(metadata.get("component"), dict) else None
    if not root or not isinstance(root.get("name"), str) or not root["name"]:
        raise SbomDocumentError("metadata.component.name is required")
    components = document.get("components")
    if not isinstance(components, list):
        raise SbomDocumentError("components must be a list")

    root_ref = root.get("bom-ref")
    if not isinstance(root_ref, str) or not root_ref:
        root_ref = None

    parent_by_ref: dict[str, str] = {}
    root_children: set[str] = set()
    for edge in document.get("dependencies") or []:
        if isinstance(edge, dict) and isinstance(edge.get("ref"), str) \
                and isinstance(edge.get("dependsOn"), list):
            is_root = root_ref is not None and edge["ref"] == root_ref
            for child in edge["dependsOn"]:
                if isinstance(child, str):
                    if is_root:
                        root_children.add(child)
                    else:
                        parent_by_ref[child] = edge["ref"]

    purl_by_ref: dict[str, str] = {}
    rows = []
    for entry in components:
        if not isinstance(entry, dict):
            raise SbomDocumentError("components entries must be objects")
        name = entry.get("name")
        if not REQUIRED_KEYS <= {"name"} or not isinstance(name, str) or not name:
            raise SbomDocumentError("every component needs a name")
        bom_ref = entry.get("bom-ref")
        purl = entry.get("purl") if isinstance(entry.get("purl"), str) and entry["purl"] else None
        if isinstance(bom_ref, str) and bom_ref and purl:
            purl_by_ref[bom_ref] = purl
        parent_ref = parent_by_ref.get(bom_ref) if isinstance(bom_ref, str) and bom_ref else None
        is_direct = bool(bom_ref and bom_ref in root_children)
        parent_purl = None
        if parent_ref and parent_ref != root_ref:
            parent_purl = purl_by_ref.get(parent_ref)
        # A root child that is ALSO a nested child (diamond) keeps its nested
        # parent for the tree view while staying direct in the list view.
        rows.append({
            "identity_key": identity_key(
                purl, name, entry.get("version") if isinstance(entry.get("version"), str) else None),
            "purl": purl,
            "bom_ref": bom_ref if isinstance(bom_ref, str) and bom_ref else None,
            "name": name,
            "version": entry.get("version") if isinstance(entry.get("version"), str) else None,
            "license": _license_of(entry),
            "manifest_path": _property_strings(entry),
            "is_direct": is_direct,
            "parent_purl": parent_purl,
        })

    version = root.get("version")
    return {
        "project_name": root["name"],
        "project_version": version if isinstance(version, str) and version else None,
        "components": rows,
    }


def content_sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def ingest_document(session, org_id: str, raw: bytes, *, source: str,
                    filename: str | None = None,
                    project_override: str | None = None,
                    version_override: str | None = None) -> dict:
    """Idempotent ingestion: one receipt per (project_version, content hash).

    Returns {'status': 'created'|'duplicate', 'import_id', ...receipt fields}.
    """
    document = json.loads(raw)
    parsed = parse(document)
    project_name = project_override or parsed["project_name"]
    version = version_override or parsed["project_version"]
    if not version:
        raise SbomDocumentError("project version required (metadata.component.version or override)")

    project = _project(session, org_id, project_name)
    project_version = _project_version(session, project, version)
    digest = content_sha256(raw)

    existing = session.query(models.SbomImport).filter_by(
        project_version_id=project_version.id, content_sha256=digest).one_or_none()
    if existing:
        return {"status": "duplicate", "import_id": existing.id,
                "receipt": receipt_of(existing, project, project_version)}

    counters = {"components_received": len(parsed["components"]),
                "components_created": 0, "components_updated": 0,
                "components_skipped": 0, "links_created": 0}
    for row in parsed["components"]:
        component = session.query(models.Component).filter_by(
            org_id=org_id, identity_key=row["identity_key"]).one_or_none()
        if component is None:
            component = models.Component(org_id=org_id, **{k: row[k] for k in
                                                           ("identity_key", "purl", "bom_ref", "name",
                                                            "version", "license", "manifest_path")})
            session.add(component)
            session.flush()  # assign the id before links reference it
            counters["components_created"] += 1
        else:
            changed = (component.version, component.license, component.manifest_path) != (
                row["version"], row["license"], row["manifest_path"])
            if changed:
                component.version = row["version"]
                component.license = row["license"]
                component.manifest_path = row["manifest_path"]
                component.updated_at = models.utcnow()
                counters["components_updated"] += 1
        link = session.query(models.VersionComponent).filter_by(
            project_version_id=project_version.id, component_id=component.id).one_or_none()
        if link is None:
            session.add(models.VersionComponent(
                project_version_id=project_version.id, component_id=component.id,
                is_direct=row["is_direct"], parent_purl=row["parent_purl"],
                manifest_path=row["manifest_path"]))
            counters["links_created"] += 1

    receipt = models.SbomImport(
        project_version_id=project_version.id, content_sha256=digest, source=source,
        filename=filename, **counters)
    session.add(receipt)
    session.flush()
    return {"status": "created", "import_id": receipt.id,
            "receipt": receipt_of(receipt, project, project_version)}


def _project(session, org_id: str, name: str) -> models.Project:
    slug = "".join(ch.lower() if ch.isalnum() else "-" for ch in name).strip("-")[:255] or "project"
    project = session.query(models.Project).filter_by(org_id=org_id, slug=slug).one_or_none()
    if project is None:
        project = models.Project(org_id=org_id, name=name, slug=slug)
        session.add(project)
        session.flush()
    return project


def _project_version(session, project: models.Project, version: str) -> models.ProjectVersion:
    row = session.query(models.ProjectVersion).filter_by(
        project_id=project.id, version=version).one_or_none()
    if row is None:
        row = models.ProjectVersion(project_id=project.id, version=version)
        session.add(row)
        session.flush()
    return row


def receipt_of(receipt: models.SbomImport, project, project_version) -> dict:
    return {
        "import_id": receipt.id,
        "project": project.name,
        "version": project_version.version,
        "source": receipt.source,
        "content_sha256": receipt.content_sha256,
        "counts": {key: getattr(receipt, key) for key in (
            "components_received", "components_created", "components_updated",
            "components_skipped", "links_created")},
        "created_at": receipt.created_at.isoformat() if receipt.created_at else None,
    }

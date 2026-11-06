"""CycloneDX SBOM ingestion: normalize a document into components + version links.

Identity: a component is keyed by `purl` when present, otherwise by its
`bom-ref`. The dependency graph decides `is_direct` (children of the SBOM's
metadata component) and `parent_purl` (the purl of the parent bom-ref). Trivy
manifest provenance is picked up from any property whose name contains
`SrcFile`.

Manifest pseudo-components are containers, not packages. Trivy describes the
file it scanned ("requirements.txt", type application) as a component with no
purl and no version, and hangs the real packages off it. Treating that node as
the parent's purl key made the whole edge disappear: 122 packages ended up with
no parent and not marked direct either, which is why the graph view had nothing
to draw.
"""
import hashlib
import json
import re
from urllib.parse import unquote

from backend.app import incidents, lifecycle, models, severity as severity_mod, vulns


class SbomDocumentError(ValueError):
    """Raised when the payload is not a workable CycloneDX document."""


REQUIRED_KEYS = {"name"}


def purl_name(purl: str | None) -> str | None:
    """The package name as its purl states it, namespace included.

    Trivy splits a scoped npm package into `name: "node"` plus `group: "@types"`,
    so storing `name` verbatim left three different packages called "node" in
    the same table — and made the parent column read "vite via vite". The purl
    is the identity of record here, so the display name comes from it:
    `pkg:npm/%40types/node@24.0.14` → `@types/node`.
    """
    if not purl or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("?", 1)[0]
    if "/" not in body:
        return None
    path = body.split("/", 1)[1]
    # A version separator is the last "@"; scopes are percent-encoded in a purl,
    # so a literal "@" before it would be malformed input.
    name = path.rsplit("@", 1)[0] if "@" in path else path
    name = unquote(name).strip()
    return name or None


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


def _licenses_of(component: dict) -> list[str]:
    """Every declared license (SPDX id/name or expression), deduped, stable."""
    found: list[str] = []
    for entry in component.get("licenses") or []:
        if not isinstance(entry, dict):
            continue
        if isinstance(entry.get("expression"), str) and entry["expression"]:
            found.append(entry["expression"].strip())
            continue
        license_block = entry.get("license")
        if isinstance(license_block, dict):
            for key in ("id", "name"):
                value = license_block.get(key)
                if isinstance(value, str) and value.strip():
                    found.append(value.strip())
                    break
    seen: set[str] = set()
    unique = []
    for item in found:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def _license_of(component: dict) -> str | None:
    licenses = _licenses_of(component)
    return licenses[0] if licenses else None


def _is_container(entry: dict) -> bool:
    """True for the scanned file itself, which CycloneDX models as a component.

    Trivy emits "requirements.txt" with `type: application`, no purl and no
    version. Such an entry documents where its children came from; it is not
    shippable software and must not be counted as a dependency.

    `type` decides, not the missing version: a library with an unknown version
    (SPDX `NOASSERTION`, an unpinned package) is still a package.
    """
    if entry.get("purl"):
        return False
    version = entry.get("version")
    if isinstance(version, str) and version.strip() and version.strip().upper() != "NOASSERTION":
        return False
    return str(entry.get("type") or "").strip().lower() in {"application", "file"}


def _graph_edges(document: dict) -> dict[str, list[str]]:
    """child bom-ref → its parent bom-refs, from the CycloneDX `dependencies`.

    A package can be named by two edges at once (a root child that is also pulled
    in transitively); keeping every parent is what lets the reader answer both
    "is it direct" and "who is its tree parent".
    """
    parents: dict[str, list[str]] = {}
    for edge in document.get("dependencies") or []:
        if not isinstance(edge, dict):
            continue
        parent_ref = edge.get("ref")
        children = edge.get("dependsOn")
        if not isinstance(parent_ref, str) or not isinstance(children, list):
            continue
        for child in children:
            if not isinstance(child, str) or child == parent_ref:
                continue
            seen = parents.setdefault(child, [])
            if parent_ref not in seen:
                seen.append(parent_ref)
    return parents


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
    if components is None:
        # A valid SBOM may declare no components at all (an iOS app with only
        # a resolved manifest, an empty service). Treat it as an empty set.
        components = []
    if not isinstance(components, list):
        raise SbomDocumentError("components must be a list")

    parents_by_ref = _graph_edges(document)
    by_ref = {entry["bom-ref"]: entry for entry in components
              if isinstance(entry, dict) and isinstance(entry.get("bom-ref"), str)
              and entry["bom-ref"]}

    def resolve(ref: str | None) -> tuple[bool, str | None, str | None]:
        """(is_direct, parent_purl, manifest) for one component bom-ref.

        The nearest *package* above decides both answers: hanging off a manifest
        container (or off the application itself) is direct and takes the
        manifest's name as provenance; hanging off another package is transitive
        and carries that purl as its tree parent.
        """
        if not ref:
            # No bom-ref means the document never placed it in the tree.
            return False, None, None
        manifest = None
        package_parent = None
        # A component the document gives no edge at all is not a declared direct
        # dependency: silence is not a claim.
        direct = False
        for parent in parents_by_ref.get(ref) or []:
            hit_package = False
            cur, seen = parent, {ref}
            while cur and cur not in seen:
                seen.add(cur)
                entry = by_ref.get(cur)
                if entry is None or _is_container(entry):
                    if manifest is None and entry is not None and isinstance(entry.get("name"), str):
                        manifest = entry["name"]
                    reached = parents_by_ref.get(cur) or []
                    cur = reached[0] if reached else None
                    continue
                hit_package = True
                purl = entry.get("purl")
                if package_parent is None and isinstance(purl, str) and purl:
                    package_parent = purl
                break
            if not hit_package:
                direct = True
        return direct, package_parent, manifest

    rows = []
    for entry in components:
        if not isinstance(entry, dict):
            raise SbomDocumentError("components entries must be objects")
        name = entry.get("name")
        if not REQUIRED_KEYS <= {"name"} or not isinstance(name, str) or not name:
            raise SbomDocumentError("every component needs a name")
        if _is_container(entry):
            continue
        bom_ref = entry.get("bom-ref")
        purl = entry.get("purl") if isinstance(entry.get("purl"), str) and entry["purl"] else None
        is_direct, parent_purl, manifest = resolve(
            bom_ref if isinstance(bom_ref, str) and bom_ref else None)
        # A root child that is ALSO a nested child (diamond) keeps its nested
        # parent for the tree view while staying direct in the list view.
        rows.append({
            "identity_key": identity_key(
                purl, name, entry.get("version") if isinstance(entry.get("version"), str) else None),
            "purl": purl,
            "bom_ref": bom_ref if isinstance(bom_ref, str) and bom_ref else None,
            # The purl wins when it names a namespace: `node` alone is not an
            # identity, `@types/node` is.
            "name": purl_name(purl) or name,
            "version": entry.get("version") if isinstance(entry.get("version"), str) else None,
            "license": _license_of(entry),
            "licenses": _licenses_of(entry),
            "manifest_path": _property_strings(entry) or manifest,
            "is_direct": is_direct,
            "parent_purl": parent_purl,
        })

    version = root.get("version")
    return {
        "project_name": root["name"],
        "project_version": version if isinstance(version, str) and version else None,
        "components": rows,
        # Named here so the writer can retire the links an older parser created
        # for them: those rows are files masquerading as packages.
        "containers": [entry.get("name") for entry in components
                       if isinstance(entry, dict) and _is_container(entry)],
        "vulnerabilities": parse_vulnerabilities(document, rows),
    }


# ---------------------------------------------------------------- vulnerabilities
# A CycloneDX document produced by a vulnerability scanner already carries the
# advisories it resolved. Parsing them here is why the platform does not need to
# query a CVE feed again: the artifact is the evidence, and re-resolving it in
# the platform would be a second opinion nobody asked for.

_VERSION_TAIL = re.compile(r"(\d+(?:\.\d+)+[A-Za-z0-9.\-]*)\s*$")


def _rating(vulnerability: dict) -> tuple[str | None, float | None, str | None]:
    """Worst severity, highest score, and the vector that score belongs to."""
    labels: list[str] = []
    scored: list[tuple[float, str]] = []
    for rating in vulnerability.get("ratings") or []:
        if not isinstance(rating, dict):
            continue
        label = rating.get("severity")
        if isinstance(label, str) and label.strip():
            labels.append(severity_mod.canonical(label))
        raw_score = rating.get("score")
        if raw_score is None or isinstance(raw_score, bool):
            continue
        try:
            score = float(raw_score)
        except (TypeError, ValueError):
            continue
        vector = rating.get("vector")
        if isinstance(vector, str) and vector:
            scored.append((score, vector))
    severity = min(labels, key=severity_mod.rank) if labels else None
    score = max((value for value, _ in scored), default=None)
    vector = next((v for s, v in scored if s == score), None) if scored else None
    return severity, score, vector


def _fixed_version(vulnerability: dict) -> str | None:
    """The upgrade target, when the scanner states one."""
    for prop in vulnerability.get("properties") or []:
        if isinstance(prop, dict) and "fixed" in str(prop.get("name", "")).lower():
            value = prop.get("value")
            if isinstance(value, str) and value.strip():
                return value.strip()
    recommendation = vulnerability.get("recommendation")
    if isinstance(recommendation, str):
        match = _VERSION_TAIL.search(recommendation.strip())
        if match:
            return match.group(1)
    return None


def _advisory_url(vulnerability: dict) -> str | None:
    for advisory in vulnerability.get("advisories") or []:
        if isinstance(advisory, dict) and isinstance(advisory.get("url"), str):
            return advisory["url"]
    source = vulnerability.get("source")
    if isinstance(source, dict) and isinstance(source.get("url"), str):
        return source["url"]
    for reference in vulnerability.get("references") or []:
        if isinstance(reference, dict) and isinstance(reference.get("url"), str):
            return reference["url"]
    return None


def parse_vulnerabilities(document: dict, components: list[dict]) -> list[dict]:
    """Normalize `vulnerabilities[]` and resolve each one to a component identity.

    A CycloneDX vulnerability points at components through `affects[].ref`, which
    is a bom-ref. Trivy uses the purl as bom-ref, but the spec does not require
    it, so both maps are built. An advisory that points at nothing resolvable is
    dropped, not attached to a guess.
    """
    by_ref: dict[str, str] = {}
    for row in components:
        for key in (row.get("bom_ref"), row.get("purl")):
            if key:
                by_ref[key] = row["identity_key"]

    out: list[dict] = []
    for entry in document.get("vulnerabilities") or []:
        if not isinstance(entry, dict):
            continue
        source_id = entry.get("id")
        if not isinstance(source_id, str) or not source_id:
            continue
        severity, score, vector = _rating(entry)
        cve_id = source_id if source_id.upper().startswith("CVE-") else next(
            (alias for alias in (entry.get("references") or [])
             if isinstance(alias, str) and alias.upper().startswith("CVE-")), None)
        identities: list[str] = []
        for affect in entry.get("affects") or []:
            if not isinstance(affect, dict):
                continue
            ref = affect.get("ref")
            identity = by_ref.get(ref) if isinstance(ref, str) else None
            if identity and identity not in identities:
                identities.append(identity)
        description = entry.get("description")
        out.append({
            "source_id": source_id,
            "cve_id": cve_id,
            "title": (description or source_id)[:512],
            "detail": description[:4000] if isinstance(description, str) else None,
            "severity": severity,
            "cvss_score": score,
            "cvss_vector": vector,
            "url": _advisory_url(entry),
            "fixed_version": _fixed_version(entry),
            "identities": identities,
        })
    return out


def content_sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def ingest_document(session, org_id: str, raw: bytes, *, source: str,
                    filename: str | None = None,
                    project_override: str | None = None,
                    version_override: str | None = None,
                    component_override: str | None = None) -> dict:
    """Idempotent ingestion: one receipt per (project_version, content hash).

    A version belongs to a component, so an SBOM for the backend must not land on
    the web's `1.7.4`. `component_override` names it; without one the document is
    a product-wide release.

    Returns {'status': 'created'|'duplicate', 'import_id', ...receipt fields}.
    """
    document = json.loads(raw)
    parsed = parse(document)
    project_name = project_override or parsed["project_name"]
    version = version_override or parsed["project_version"]
    if not version:
        raise SbomDocumentError("project version required (metadata.component.version or override)")

    project = _project(session, org_id, project_name)
    component_id = None
    if component_override:
        component = _component(session, project, component_override)
        component_id = component.id
    project_version = _project_version(session, project, version, component_id)
    digest = content_sha256(raw)

    existing = session.query(models.SbomImport).filter_by(
        project_version_id=project_version.id, content_sha256=digest).one_or_none()
    if existing:
        return {"status": "duplicate", "import_id": existing.id,
                "receipt": receipt_of(existing, project, project_version)}

    counters = {"components_received": len(parsed["components"]),
                "components_created": 0, "components_updated": 0,
                "components_skipped": 0, "links_created": 0,
                "vulnerabilities_received": len(parsed["vulnerabilities"]),
                "vulnerabilities_created": 0, "vulnerabilities_refreshed": 0,
                "vulnerabilities_unresolved": 0}
    # A real SBOM repeats the same component when several manifests pull it in.
    # The session runs with autoflush=False, so a query cannot see rows added
    # earlier in this loop: track them here or the unique constraints
    # (version, component) and (component, license) fail on the second sighting.
    linked: dict[str, models.VersionComponent] = {}
    by_identity: dict[str, models.Component] = {}
    seen_licenses: set[tuple[str, str]] = set()
    # A document that names its own manifests also tells us which links an older
    # parser created for those files: drop them for this version so the
    # inventory stops counting "requirements.txt" as software.
    for container_name in parsed.get("containers") or []:
        if not container_name:
            continue
        stale = (session.query(models.VersionComponent)
                 .join(models.Component, models.Component.id == models.VersionComponent.component_id)
                 .filter(models.VersionComponent.project_version_id == project_version.id,
                         models.Component.org_id == org_id,
                         models.Component.name == container_name,
                         models.Component.purl.is_(None),
                         models.Component.version.is_(None)).all())
        for link in stale:
            session.delete(link)
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
            # The name is part of the repair: a document that finally carries the
            # namespace must be able to rename an old bare "node" row, the same
            # way a better graph repairs `parent_purl`.
            changed = (component.name, component.version, component.license,
                       component.manifest_path) != (
                row["name"], row["version"], row["license"], row["manifest_path"])
            if changed:
                component.name = row["name"]
                component.version = row["version"]
                component.license = row["license"]
                component.manifest_path = row["manifest_path"]
                component.updated_at = models.utcnow()
                counters["components_updated"] += 1
        # BL-060: full license set (idempotent rows; never duplicated on
        # re-ingest thanks to uq(component, license)).
        for license_id in row.get("licenses") or []:
            license_key = (component.id, license_id)
            if license_key in seen_licenses:
                continue
            seen_licenses.add(license_key)
            exists = (session.query(models.ComponentLicense)
                      .filter_by(component_id=component.id, license_id=license_id)
                      .one_or_none())
            if exists is None:
                session.add(models.ComponentLicense(
                    org_id=org_id, component_id=component.id,
                    license_id=license_id, created_at=models.utcnow()))
        link = linked.get(component.id)
        if link is None:
            link = (session.query(models.VersionComponent)
                    .filter_by(project_version_id=project_version.id,
                               component_id=component.id).one_or_none())
        if link is None:
            link = models.VersionComponent(
                project_version_id=project_version.id, component_id=component.id,
                is_direct=row["is_direct"], parent_purl=row["parent_purl"],
                manifest_path=row["manifest_path"])
            session.add(link)
            counters["links_created"] += 1
        else:
            # The same component seen both directly and transitively is direct.
            if row["is_direct"]:
                link.is_direct = True
            # A re-ingested document that finally carries a graph has to repair
            # the link: storing the tree write-once left every version flat
            # forever, no matter how good the next BOM was.
            if (link.parent_purl, link.manifest_path) != (row["parent_purl"], row["manifest_path"]):
                link.parent_purl = row["parent_purl"]
                link.manifest_path = row["manifest_path"]
        linked[component.id] = link
        by_identity[row["identity_key"]] = component

    _ingest_vulnerabilities(session, org_id, project, project_version, parsed["vulnerabilities"],
                            by_identity, counters)

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


def _component(session, project: models.Project, name: str) -> models.ApplicationComponent:
    """Resolve a component by slug or name; an SBOM may not invent one."""
    slug = "".join(ch.lower() if ch.isalnum() else "-" for ch in name).strip("-")[:128]
    row = (session.query(models.ApplicationComponent)
           .filter(models.ApplicationComponent.project_id == project.id,
                   (models.ApplicationComponent.slug == slug)
                   | (models.ApplicationComponent.name == name)).one_or_none())
    if row is None:
        raise SbomDocumentError(
            f"component not found in {project.name}: {name} (create it in the project first)")
    return row


def _project_version(session, project: models.Project, version: str,
                     component_id: str | None = None) -> models.ProjectVersion:
    row = session.query(models.ProjectVersion).filter_by(
        project_id=project.id, version=version, component_id=component_id).one_or_none()
    if row is None:
        row = models.ProjectVersion(project_id=project.id, version=version,
                                    component_id=component_id)
        session.add(row)
        session.flush()
    return row


def _ingest_vulnerabilities(session, org_id: str, project: models.Project,
                            project_version: models.ProjectVersion, entries: list[dict],
                            by_identity: dict[str, models.Component],
                            counters: dict) -> None:
    """Advisories become deduped findings, one per (component, advisory).

    The identity is the same one the OSV engine uses, so an artifact-resolved
    CVE and a feed-resolved CVE are the same finding instead of two rows with
    different sources.
    """
    now = models.utcnow()
    for entry in entries:
        identities = [identity for identity in entry["identities"] if identity in by_identity]
        if not identities:
            # The advisory names a package the document does not contain.
            # Attaching it to a guess would invent an affected asset.
            counters["vulnerabilities_unresolved"] += 1
            continue
        advisory = _advisory(session, entry, now)
        detail = json.dumps({
            "source_id": advisory.source_id,
            "cve_id": advisory.cve_id,
            "cvss_score": entry["cvss_score"],
            "cvss_vector": entry["cvss_vector"],
            "fixed_version": entry["fixed_version"],
            "advisory_url": entry["url"],
        }, sort_keys=True)
        recommendation = (f"Upgrade to {entry['fixed_version']}" if entry["fixed_version"]
                          else "No fixed version published yet")
        rule_id = advisory.cve_id or advisory.source_id
        for identity in identities:
            component = by_identity[identity]
            fingerprint = vulns.vulnerability_fingerprint(
                org_id, project.id, identity, advisory.source_id)
            finding = (session.query(models.Finding)
                       .filter_by(org_id=org_id, fingerprint=fingerprint).one_or_none())
            if finding is None:
                # The clock may have already reported this CVE under a GHSA id.
                # One advisory, one finding: the artifact then refreshes that
                # row (and re-points it at its own advisory, which carries the
                # fixed version) instead of adding a twin.
                finding = vulns.finding_for_cve(session, org_id, project.id,
                                                component.id, advisory.cve_id)
            if finding is None:
                finding = models.Finding(
                    org_id=org_id, project_id=project.id, kind="vulnerability",
                    vector="dependency-cve", fingerprint=fingerprint, source="sbom",
                    title=advisory.title, severity=advisory.severity, url=advisory.url,
                    detail=detail, tool="trivy", rule_id=rule_id,
                    component_id=component.id, vulnerability_id=advisory.id,
                    last_seen_version_id=project_version.id,
                    recommendation=recommendation,
                    first_seen_at=now, last_seen_at=now, updated_at=now)
                session.add(finding)
                session.flush()
                lifecycle.apply_lifecycle(session, org_id, finding)
                counters["vulnerabilities_created"] += 1
            else:
                finding.last_seen_at = now
                finding.last_seen_version_id = project_version.id
                finding.kind = "vulnerability"
                finding.vector = "dependency-cve"
                finding.severity = advisory.severity
                finding.title = advisory.title
                finding.detail = detail
                finding.recommendation = recommendation
                finding.component_id = component.id
                finding.vulnerability_id = advisory.id
                finding.updated_at = now
                counters["vulnerabilities_refreshed"] += 1
            incidents.record_occurrence(
                session, org_id, finding, project_version.id, "trivy", "sbom",
                kind="vulnerability", rule_id=rule_id, path=None, line=None,
                detail=advisory.title, now=now)


def _advisory(session, entry: dict, now) -> models.Vulnerability:
    """Upsert the global advisory catalog from the artifact's own statement."""
    advisory = (session.query(models.Vulnerability)
                .filter_by(source_id=entry["source_id"]).one_or_none())
    if advisory is None:
        advisory = models.Vulnerability(
            source_id=entry["source_id"], source="sbom", cve_id=entry["cve_id"],
            title=entry["title"], severity=entry["severity"],
            cvss_vector=entry["cvss_vector"], url=entry["url"], fetched_at=now)
        session.add(advisory)
        session.flush()
        return advisory
    # The artifact is newer than the catalog row it matches.
    advisory.cve_id = entry["cve_id"] or advisory.cve_id
    advisory.title = entry["title"] or advisory.title
    advisory.severity = entry["severity"] or advisory.severity
    advisory.cvss_vector = entry["cvss_vector"] or advisory.cvss_vector
    advisory.url = entry["url"] or advisory.url
    advisory.fetched_at = now
    return advisory


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

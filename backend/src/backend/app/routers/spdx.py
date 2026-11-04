"""BL-025: SPDX 2.3 JSON export alongside the CycloneDX ingest/export path."""
import json

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.versions import pick_version
from backend.app import auth, models
from backend.app.db import get_session

router = APIRouter(prefix="/api/v1", tags=["spdx"])


@router.get("/spdx/export")
def export_spdx(project: str = Query(...), version: str = Query(...),
                org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    """SPDX 2.3 document for one project version (packages = components)."""
    proj = (session.query(models.Project)
            .filter_by(org_id=org.id, slug=project).one_or_none())
    if proj is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    pv = (pick_version(session, proj.id, version))
    if pv is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project version not found")

    rows = (session.query(models.VersionComponent, models.Component)
            .join(models.Component, models.VersionComponent.component_id == models.Component.id)
            .filter(models.VersionComponent.project_version_id == pv.id).all())

    packages = []
    relationships = []
    seen = set()
    for index, (link, component) in enumerate(rows, start=1):
        spdx_id = f"SPDXRef-Package-{index}"
        if component.id in seen:
            continue
        seen.add(component.id)
        licenses = [row.license_id for row in
                    (session.query(models.ComponentLicense)
                     .filter_by(component_id=component.id).all())]
        package = {
            "SPDXID": spdx_id,
            "name": component.name or component.identity_key,
            "versionInfo": component.version or "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": " AND ".join(sorted(licenses))
            if licenses else "NOASSERTION",
        }
        if component.purl:
            package["externalRefs"] = [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": component.purl,
            }]
        packages.append(package)
        relationships.append({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": spdx_id,
        })

    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{proj.slug}@{pv.version}",
        "documentNamespace": f"https://barad-dur.local/spdx/{org.slug}/{proj.slug}/{pv.version}",
        "creationInfo": {
            "created": models.utcnow().isoformat(),
            "creators": ["Tool: barad-dur-platform"],
        },
        "packages": packages,
        "relationships": relationships,
    }
    return document


def _cyclonedx_from_spdx(document: dict) -> dict:
    """Translate an SPDX 2.3 JSON document into the CycloneDX shape we ingest.

    Only the fields that carry security meaning are mapped: identity (name,
    version, purl) and declared licenses. Everything else is dropped rather
    than invented.
    """
    packages = document.get("packages") or []
    if not isinstance(packages, list) or not packages:
        raise ValueError("SPDX document has no packages")
    components = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        if not name or name == "NOASSERTION":
            continue
        version = package.get("versionInfo")
        if version in (None, "", "NOASSERTION"):
            version = None
        purl = None
        for reference in package.get("externalRefs") or []:
            if (reference or {}).get("referenceType") == "purl":
                purl = reference.get("referenceLocator")
                break
        licenses = []
        declared = package.get("licenseDeclared")
        if declared and declared not in ("NOASSERTION", "NONE"):
            for token in str(declared).replace("(", " ").replace(")", " ").split():
                if token in ("AND", "OR", "WITH"):
                    continue
                licenses.append({"license": {"id": token}})
        component = {"type": "library", "name": name}
        if version:
            component["version"] = version
        if purl:
            component["purl"] = purl
        if licenses:
            component["licenses"] = licenses
        components.append(component)
    if not components:
        raise ValueError("SPDX document produced no usable packages")
    publisher = ((document.get("creationInfo") or {}).get("creators") or ["spdx"])[0]
    return {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "metadata": {"component": {"type": "application",
                                       "name": document.get("name") or "spdx-import",
                                       "author": publisher[:120]}},
            "components": components}


@router.post("/spdx/import")
def import_spdx(body: dict = Body(...),
                project: str | None = Query(default=None),
                version: str | None = Query(default=None),
                org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    """Ingest an SPDX 2.3 JSON document through the CycloneDX pipeline."""
    from backend.app import ingest
    from backend.app.routers.sbom import ReceiptResponse

    if (body or {}).get("spdxVersion") is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "not an SPDX document (spdxVersion missing)")
    try:
        converted = _cyclonedx_from_spdx(body)
        raw = json.dumps(converted).encode()
        result = ingest.ingest_document(
            session, org.id, raw, source="api", filename="spdx-import.json",
            project_override=project or converted["metadata"]["component"]["name"],
            version_override=version)
    except (ValueError, ingest.SbomDocumentError) as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from None
    session.commit()
    return ReceiptResponse.model_validate(result, from_attributes=True)

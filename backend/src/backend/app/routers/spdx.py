"""BL-025: SPDX 2.3 JSON export alongside the CycloneDX ingest/export path."""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

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
    pv = (session.query(models.ProjectVersion)
          .filter_by(project_id=proj.id, version=version).one_or_none())
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

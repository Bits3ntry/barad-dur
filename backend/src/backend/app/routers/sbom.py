"""SBOM ingestion endpoints."""
import json

from fastapi import APIRouter, Depends, Body, HTTPException, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.app import auth, ingest, models
from backend.app.db import get_session

router = APIRouter(prefix="/api/v1", tags=["sbom"])

MAX_BODY_BYTES = 50 * 1024 * 1024  # 50 MB, matching the reference platform's contract floor
ALLOWED_SOURCES = ("cli", "web", "ci", "api")


class ReceiptResponse(BaseModel):
    status: str
    import_id: str
    receipt: dict


@router.post("/sbom", response_model=ReceiptResponse)
def upload_sbom(
    body: bytes = Body(...),
    project: str | None = Query(default=None, description="project name override"),
    version: str | None = Query(default=None, description="project version override"),
    source: str = Query(default="api"),
    filename: str | None = Query(default=None),
    org: models.Organization = Depends(auth.require_org),
    session: Session = Depends(get_session),
):
    """Ingest a raw CycloneDX JSON SBOM body; idempotent per key triple.

    201 for a new receipt, 200 when the same content already landed for that
    project+version. `source` declares the delivery channel ('cli', 'web',
    'ci', 'api'); it carries no security meaning by itself.
    """
    if source not in ALLOWED_SOURCES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid source")
    if len(body) > MAX_BODY_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "SBOM body exceeds 50 MB")
    if not body.lstrip()[:1] == b"{":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "body must be a JSON object")
    try:
        result = ingest.ingest_document(
            session, org.id, body, source=source, filename=filename,
            project_override=project, version_override=version)
    except (ingest.SbomDocumentError, ValueError, json.JSONDecodeError) as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from None
    session.commit()
    status_code = 201 if result["status"] == "created" else 200
    return JSONResponse(status_code=status_code, content=ReceiptResponse.model_validate(
        result, from_attributes=True).model_dump())


@router.get("/imports/{import_id}")
def get_import(import_id: str, org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    receipt = session.get(models.SbomImport, import_id)
    if receipt is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "import not found")
    project_version = session.get(models.ProjectVersion, receipt.project_version_id)
    project = session.get(models.Project, project_version.project_id)
    if project.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "import not found")
    return {"data": ingest.receipt_of(receipt, project, project_version)}

"""Trivy DB updater — offline sign/publish workflow (GAP-08)."""

import hashlib
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from backend.app import auth, models
from backend.app.db import get_session
from sqlalchemy.orm import Session

router = APIRouter(prefix="/api/v1", tags=["trivy-db"])

SANDBOX_DIR = "/var/lib/barad/trivy-sandbox"
PUBLISH_DIR = "/var/lib/barad/trivy-publish"
LOGS_DIR = "/var/lib/barad/trivy-logs"

class TrivyDbUpdate(BaseModel):
    id: str
    org_id: str
    status: str
    target_filename: str | None
    target_size: int
    target_sha256: str | None
    header_version: str | None
    error: str | None
    created_at: str
    last_scheduled_at: str | None
    last_successful_at: str | None


@router.post("/easm/trivy-db/updates", status_code=status.HTTP_202_ACCEPTED)
def start_trivy_db_update(
        org: models.Organization = Depends(auth.require_org),
        session: Session = Depends(get_session)):
    """Initiate a Trivy DB fetch/update with offline signing."""
    update_id = models.uuid_hex()
    row = models.TrivyDbUpdate(
        id=update_id, org_id=org.id, status="pending")
    session.add(row)
    session.commit()

    try:
        _run_update(update_id)
        session.refresh(row)
        session.commit()
    except Exception as e:
        row.status = "failed"
        row.error = str(e)
        session.commit()
        raise HTTPException(
            status_code=502, detail=f"Trivy DB update failed: {e}")

    return {"id": row.id, "status": row.status}


def _run_update(update_id: str):
    workdir = tempfile.mkdtemp(prefix="trivy-update-")
    try:
        # 1) Fetch
        os.makedirs(SANDBOX_DIR, exist_ok=True)
        os.makedirs(LOGS_DIR, exist_ok=True)
        fetch_path = os.path.join(SANDBOX_DIR, "trivy.db")
        with open(os.path.join(LOGS_DIR, f"{update_id}.fetch.log"), "w") as lf:
            subprocess.run(
                ["trivy", "db", "download", "--output", fetch_path],
                check=True, capture_output=True, text=True, timeout=600,
                stdout=lf, stderr=lf)

        # 2) Verify checksum / signature (offline)
        with open(os.path.join(LOGS_DIR, f"{update_id}.verify.log"), "w") as lf:
            subprocess.run(
                ["trivy", "db", "verify", "--source", fetch_path],
                check=True, capture_output=True, text=True, timeout=120,
                stdout=lf, stderr=lf)

        # 3) Publish to read-only sandbox
        pub_path = os.path.join(PUBLISH_DIR, "trivy.db")
        os.makedirs(PUBLISH_DIR, exist_ok=True)
        shutil.copy2(fetch_path, pub_path)
        os.chmod(PUBLISH_DIR, 0o555)

        # 4) Record in DB
        with open(fetch_path, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        header = subprocess.run(
            ["trivy", "db", "header", "--source", fetch_path],
            capture_output=True, text=True, timeout=30)
        header_version = header.stdout.strip() or header.stderr.strip()

        # Update the in-DB record
        row = session.query(models.TrivyDbUpdate).filter_by(id=update_id).one()
        row.status = "completed"
        row.target_filename = "trivy.db"
        row.target_size = os.path.getsize(fetch_path)
        row.target_sha256 = digest
        row.header_version = header_version
        row.last_successful_at = models.utcnow()
        session.commit()
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


@router.get("/easm/trivy-db/updates/{update_id}", response_model=list[TrivyDbUpdate])
def trivy_db_update_status(update_id: str,
                           org: models.Organization = Depends(auth.require_org)):
    rows = (session.query(models.TrivyDbUpdate)
            .filter_by(org_id=org.id, id=update_id).all())
    return [{"id": r.id, "status": r.status,
             "target_filename": r.target_filename,
             "target_size": r.target_size,
             "target_sha256": r.target_sha256,
             "header_version": r.header_version,
             "error": r.error,
             "created_at": r.created_at.isoformat(),
             "last_scheduled_at": r.last_scheduled_at.isoformat() if r.last_scheduled_at else None,
             "last_successful_at": r.last_successful_at.isoformat() if r.last_successful_at else None}
            for r in rows]


@router.get("/easm/trivy-db/updates", response_model=list[TrivyDbUpdate])
def trivy_db_updates(
        org: models.Organization = Depends(auth.require_org),
        session: Session = Depends(get_session)):
    rows = (session.query(models.TrivyDbUpdate)
            .filter_by(org_id=org.id)
            .order_by(models.TrivyDbUpdate.created_at.desc())
            .limit(50)
            .all())
    return [{"id": r.id, "status": r.status,
             "target_filename": r.target_filename,
             "target_size": r.target_size,
             "target_sha256": r.target_sha256,
             "header_version": r.header_version,
             "error": r.error,
             "created_at": r.created_at.isoformat(),
             "last_scheduled_at": r.last_scheduled_at.isoformat() if r.last_scheduled_at else None,
             "last_successful_at": r.last_successful_at.isoformat() if r.last_successful_at else None}
            for r in rows]


@router.get("/easm/trivy-db/updates/freshness")
def trivy_db_freshness(
        org: models.Organization = Depends(auth.require_org),
        session: Session = Depends(get_session)):
    """Freshness indicator: age of the last successful DB update."""
    latest = (session.query(models.TrivyDbUpdate)
              .filter_by(org_id=org.id, status="completed")
              .order_by(models.TrivyDbUpdate.last_successful_at.desc())
              .first())
    now = models.utcnow()
    if latest and latest.last_successful_at:
        age = (now - _aware(latest.last_successful_at)).total_seconds() / 3600
        return {"last_successful_at": latest.last_successful_at.isoformat(),
                "age_hours": round(age, 2),
                "fresh": age < 24}
    return {"last_successful_at": None, "age_hours": None, "fresh": False}


def _aware(value):
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value

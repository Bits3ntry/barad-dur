"""Trivy DB updater — offline fetch/verify/publish workflow (GAP-08).

The platform never scans with a database fetched from the network at scan
time: the updater downloads the DB, verifies it, publishes it into a
read-only directory and records the artifact (size, SHA-256, header version)
so the console can show how fresh the data is. When the `trivy` binary is not
installed in the deployment the updater answers 503 instead of pretending to
work.
"""

import hashlib
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from backend.app import auth, models
from backend.app.db import get_session

router = APIRouter(prefix="/api/v1", tags=["trivy-db"])

# The platform image runs unprivileged, so the defaults must be writable by it.
SANDBOX_DIR = os.environ.get("TRIVY_SANDBOX_DIR", "/tmp/barad-trivy/sandbox")
PUBLISH_DIR = os.environ.get("TRIVY_PUBLISH_DIR", "/tmp/barad-trivy/publish")
LOGS_DIR = os.environ.get("TRIVY_LOGS_DIR", "/tmp/barad-trivy/logs")

FRESH_HOURS = 24.0


class TrivyDbUpdateOut(BaseModel):
    """One updater run, as the console reads it."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    org_id: str
    status: str
    target_filename: str | None = None
    target_size: int = 0
    target_sha256: str | None = None
    header_version: str | None = None
    error: str | None = None
    created_at: datetime
    last_scheduled_at: datetime | None = None
    last_successful_at: datetime | None = None


def _trivy_bin() -> str | None:
    return shutil.which("trivy")


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _run_update(session: Session, row: models.TrivyDbUpdate) -> None:
    """Fetch, verify and publish the DB, recording the outcome on ``row``."""
    trivy = _trivy_bin()
    if trivy is None:
        row.status = "failed"
        row.error = ("trivy_unavailable: the trivy CLI is not installed in "
                     "this deployment")
        session.commit()
        return
    workdir = tempfile.mkdtemp(prefix="trivy-update-")
    try:
        for path in (SANDBOX_DIR, PUBLISH_DIR, LOGS_DIR):
            os.makedirs(path, exist_ok=True)
        fetch_path = os.path.join(SANDBOX_DIR, "trivy.db")

        with open(os.path.join(LOGS_DIR, f"{row.id}.fetch.log"), "w") as log:
            subprocess.run([trivy, "db", "download", "--output", fetch_path],
                           check=True, capture_output=True, text=True,
                           timeout=600, stdout=log, stderr=log)
        with open(os.path.join(LOGS_DIR, f"{row.id}.verify.log"), "w") as log:
            subprocess.run([trivy, "db", "verify", "--source", fetch_path],
                           check=True, capture_output=True, text=True,
                           timeout=120, stdout=log, stderr=log)

        published = os.path.join(PUBLISH_DIR, "trivy.db")
        shutil.copy2(fetch_path, published)
        os.chmod(published, 0o444)

        with open(fetch_path, "rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()
        header = subprocess.run([trivy, "db", "header", "--source", fetch_path],
                                capture_output=True, text=True, timeout=30)

        row.status = "completed"
        row.target_filename = "trivy.db"
        row.target_size = os.path.getsize(fetch_path)
        row.target_sha256 = digest
        row.header_version = (header.stdout or header.stderr or "").strip()[:64] or None
        row.last_successful_at = models.utcnow()
        row.error = None
    except Exception as exc:  # recorded, never swallowed
        row.status = "failed"
        row.error = str(exc)[:2000]
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
        session.commit()


@router.post("/easm/trivy-db/updates", status_code=status.HTTP_202_ACCEPTED,
             response_model=TrivyDbUpdateOut)
def start_trivy_db_update(org: models.Organization = Depends(auth.require_org),
                          session: Session = Depends(get_session)):
    """Run a Trivy DB fetch/verify/publish and record the artifact."""
    if _trivy_bin() is None:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "trivy_unavailable: the trivy CLI is not installed in this "
            "deployment, so the offline DB updater is disabled")

    row = models.TrivyDbUpdate(org_id=org.id, status="running",
                               last_scheduled_at=models.utcnow())
    session.add(row)
    session.commit()
    _run_update(session, row)
    return row


@router.get("/easm/trivy-db/updates/freshness")
def trivy_db_freshness(org: models.Organization = Depends(auth.require_org),
                       session: Session = Depends(get_session)):
    """Age of the newest successfully published DB."""
    latest = (session.query(models.TrivyDbUpdate)
              .filter_by(org_id=org.id, status="completed")
              .order_by(models.TrivyDbUpdate.last_successful_at.desc())
              .first())
    if latest is None or latest.last_successful_at is None:
        return {"last_successful_at": None, "age_hours": None, "fresh": False,
                "stale_after_hours": FRESH_HOURS}
    age_hours = (models.utcnow() - _aware(latest.last_successful_at)).total_seconds() / 3600
    return {"last_successful_at": latest.last_successful_at.isoformat(),
            "age_hours": round(age_hours, 2),
            "fresh": age_hours < FRESH_HOURS,
            "stale_after_hours": FRESH_HOURS}


@router.get("/easm/trivy-db/updates/{update_id}", response_model=TrivyDbUpdateOut)
def trivy_db_update_status(update_id: str,
                           org: models.Organization = Depends(auth.require_org),
                           session: Session = Depends(get_session)):
    row = (session.query(models.TrivyDbUpdate)
           .filter_by(org_id=org.id, id=update_id).one_or_none())
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "update not found")
    return row


@router.get("/easm/trivy-db/updates", response_model=list[TrivyDbUpdateOut])
def trivy_db_updates(org: models.Organization = Depends(auth.require_org),
                     session: Session = Depends(get_session)):
    return (session.query(models.TrivyDbUpdate)
            .filter_by(org_id=org.id)
            .order_by(models.TrivyDbUpdate.created_at.desc())
            .limit(50)
            .all())

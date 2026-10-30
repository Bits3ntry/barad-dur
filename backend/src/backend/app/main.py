"""FastAPI application factory."""
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.auth import create_key, require_org
from backend.app.db import get_session, run_migrations
from backend.app import models
from backend.app.routers import findings, inventory, sbom

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session


def create_app() -> FastAPI:
    app = FastAPI(title="Barad-dûr platform", version="0.1.0")
    app.include_router(sbom.router)
    app.include_router(inventory.router)
    app.include_router(findings.router)

    @app.get("/healthz")
    def healthz(session: Session = Depends(get_session)):
        try:
            session.execute(text("SELECT 1"))
        except Exception:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "database unreachable")
        return {"status": "ok"}

    management = APIRouter(prefix="/api/v1", tags=["management"])

    @management.post("/keys")
    def register_key(label: str = Query(default=""),
                     org: models.Organization = Depends(require_org),
                     session: Session = Depends(get_session)):
        """Issue a new API key for the caller's own organization.

        Not a bootstrap path: it requires an already-valid key. Bootstrap is
        the CLI command `barad-platform key create`, which writes the first key
        with database access instead of API access.
        """
        raw = create_key(session, org.id, label)
        return {"data": {"api_key": raw, "label": label}}

    app.include_router(management)
    return app


app = create_app()


def initialize() -> None:
    run_migrations()

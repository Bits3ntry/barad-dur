"""FastAPI application factory."""
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.auth import create_key, require_admin, require_org
from backend.app.db import get_session, run_migrations
from backend.app import models
from backend.app.routers import authorization as authorization_router

from backend.app.routers import accounts, analysis, artifacts, attack_surface, ci, code_baselines, code_review, ctem, cycles, dashboard, easm, easm_trivy, exposures, findings, gates as gates_router, identity, impact, intelligence, inventory, inventory_groups, jira, lifecycle, licenses as licenses_router, mfa as mfa_router, notifications, orchestration, organization, pentest, regression, relationships, schedules, sarif, scope, sbom, spdx, vulnerabilities, work

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session


def create_app() -> FastAPI:
    app = FastAPI(title="Barad-dûr platform", version="0.1.0")
    app.include_router(sbom.router)
    app.include_router(inventory.router)
    app.include_router(inventory_groups.router)
    app.include_router(vulnerabilities.router)
    app.include_router(analysis.router)
    app.include_router(exposures.router)
    app.include_router(attack_surface.router)
    app.include_router(cycles.router)
    app.include_router(artifacts.router)
    app.include_router(mfa_router.router)
    app.include_router(impact.router)
    app.include_router(work.router)
    app.include_router(findings.router)
    app.include_router(ci.router)
    app.include_router(scope.router)
    app.include_router(lifecycle.router)
    app.include_router(identity.router)
    app.include_router(intelligence.router)
    app.include_router(easm.router)
    app.include_router(easm_trivy.router)
    app.include_router(relationships.router)
    app.include_router(authorization_router.router)
    app.include_router(licenses_router.router)
    app.include_router(gates_router.router)
    app.include_router(sarif.router)
    app.include_router(ctem.router)
    app.include_router(dashboard.router)
    app.include_router(spdx.router)
    app.include_router(pentest.router)
    app.include_router(jira.router)
    app.include_router(regression.router)
    app.include_router(orchestration.router)
    app.include_router(code_review.router)
    app.include_router(code_baselines.router)
    app.include_router(accounts.router)
    app.include_router(schedules.router)
    app.include_router(notifications.router)
    app.include_router(organization.router)

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
                     org: models.Organization = Depends(require_admin),
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

"""Advisories: the daily clock and the settings it obeys.

Two surfaces, one owner. `/settings` is what an operator can change from Ajustes
(which sources run, how often, how many builds per sweep); `/tick` is what the
scheduler calls. The tick is deliberately cheap when it is not due, so a
one-minute scheduler and a twenty-four-hour interval can coexist without
hammering OSV.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import advisories, auth, models
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1/advisories", tags=["advisories"])


class SettingsIn(BaseModel):
    """A partial update: only the keys sent are changed."""

    enabled: bool | None = None
    kev: bool | None = None
    epss: bool | None = None
    osv: bool | None = None
    interval_hours: int | None = Field(default=None, ge=1, le=168)
    max_versions: int | None = Field(default=None, ge=1, le=500)
    ecosystems: list[str] | None = None
    actor: str | None = Field(default=None, max_length=255)


class TickIn(BaseModel):
    actor: str = Field(default="advisories", min_length=2, max_length=255)
    # An operator asking for a run now is a decision; the scheduler asking again
    # is not. Only the first may ignore the interval.
    force: bool = False


@router.get("/settings")
def read_settings(org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    """The effective configuration: defaults, database row and last run."""
    return {"data": advisories.load(session)}


@router.put("/settings")
def write_settings(payload: SettingsIn = None,
                   org: models.Organization = Depends(auth.require_admin),
                   session: Session = Depends(get_session)):
    """Save the knobs. Absent fields keep their current value."""
    payload = payload or SettingsIn()
    data = advisories.save(session, payload.model_dump(exclude_none=True), payload.actor)
    _audit_log(session, org.id, payload.actor or "operator", "advisories.settings",
               "platform_setting", advisories.ROW_NAME,
               f"enabled={data['enabled']} kev={data['kev']} epss={data['epss']} "
               f"osv={data['osv']} interval={data['interval_hours']}h")
    session.commit()
    return {"data": data}


@router.post("/tick", status_code=status.HTTP_200_OK)
def tick(payload: TickIn = None,
         org: models.Organization = Depends(auth.require_admin),
         session: Session = Depends(get_session)):
    """Refresh the catalogues and re-resolve the current builds, when due."""
    payload = payload or TickIn()
    counters = advisories.run(session, org.id, force=payload.force)
    if counters["status"] in ("ok", "failed"):
        _audit_log(session, org.id, payload.actor, "advisories.ticked", None, None,
                   f"{counters['status']} versions={counters['versions_analyzed']} "
                   f"created={counters['findings_created']} "
                   f"refreshed={counters['findings_refreshed']} "
                   f"kev={counters['kev_rows']} epss={counters['epss_rows']}")
    session.commit()
    return {"data": counters}

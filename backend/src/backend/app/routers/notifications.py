"""SLA notifications: signed webhook deliveries with dedupe.

A tick inspects open findings past their SLA deadline and delivers one
aggregated `sla.breached` event per channel per day, signed with
`X-Barad-Signature: sha256=<hmac>` so receivers can verify authenticity.
Failures are recorded, never swallowed, and never retried in a tight loop.
"""
import datetime
import hashlib
import hmac
import json
import secrets
import urllib.error
import urllib.request

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, auth_local, models
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1/notifications", tags=["notifications"])

EVENTS = {"sla.breached", "test"}
NON_OPEN = {"resolved", "false_positive", "suppressed"}


def _channel_data(row: models.NotificationChannel) -> dict:
    return {"id": row.id, "name": row.name, "kind": row.kind, "url": row.url,
            "events": json.loads(row.events or "[]"), "enabled": row.enabled,
            "created_at": row.created_at.isoformat()}


class ChannelIn(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    url: str = Field(min_length=8, max_length=2048)
    events: list[str] = ["sla.breached"]
    secret: str | None = None
    actor: str = Field(min_length=2, max_length=255)


@router.post("/channels")
def create_channel(payload: ChannelIn = None,
                   org: models.Organization = Depends(auth.require_admin),
                   session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if not payload.url.lower().startswith(("http://", "https://")):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "url must be http(s)")
    unknown = set(payload.events) - EVENTS
    if unknown:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"unknown events: {sorted(unknown)}")
    if session.query(models.NotificationChannel).filter_by(
            org_id=org.id, name=payload.name).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "channel name already used")
    row = models.NotificationChannel(
        org_id=org.id, name=payload.name, url=payload.url,
        secret=payload.secret or secrets.token_urlsafe(24),
        events=json.dumps(payload.events), enabled=True,
        created_at=models.utcnow())
    session.add(row)
    session.flush()
    _audit_log(session, org.id, payload.actor, "notifications.channel_created",
               "notification_channel", row.id, payload.name)
    session.commit()
    # The signing secret is shown once at creation so receivers can be configured.
    return {"data": {**_channel_data(row), "secret": row.secret}}


@router.get("/channels")
def list_channels(org: models.Organization = Depends(auth.require_admin),
                  session: Session = Depends(get_session)):
    rows = (session.query(models.NotificationChannel).filter_by(org_id=org.id)
            .order_by(models.NotificationChannel.name).all())
    return {"data": [_channel_data(r) for r in rows], "total": len(rows)}


class ChannelPatch(BaseModel):
    enabled: bool | None = None
    events: list[str] | None = None
    actor: str = Field(min_length=2, max_length=255)


@router.patch("/channels/{channel_id}")
def patch_channel(channel_id: str, payload: ChannelPatch = None,
                  org: models.Organization = Depends(auth.require_admin),
                  session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    row = session.get(models.NotificationChannel, channel_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "channel not found")
    if payload.enabled is not None:
        row.enabled = payload.enabled
    if payload.events is not None:
        unknown = set(payload.events) - EVENTS
        if unknown:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"unknown events: {sorted(unknown)}")
        row.events = json.dumps(payload.events)
    _audit_log(session, org.id, payload.actor, "notifications.channel_updated",
               "notification_channel", row.id, f"enabled={row.enabled}")
    session.commit()
    return {"data": _channel_data(row)}


def deliver(channel: models.NotificationChannel, event: str,
            payload: dict) -> tuple[int | None, str | None]:
    body = json.dumps({"event": event, "channel": channel.name,
                       "payload": payload}, sort_keys=True).encode()
    signature = hmac.new(channel.secret.encode(), body, hashlib.sha256).hexdigest()
    request = urllib.request.Request(channel.url, data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    request.add_header("X-Barad-Event", event)
    request.add_header("X-Barad-Signature", f"sha256={signature}")
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            return response.status, None
    except urllib.error.HTTPError as exc:
        return exc.code, f"http_{exc.code}: {exc.read()[:200].decode(errors='replace')}"
    except urllib.error.URLError as exc:
        return None, f"unreachable: {exc.reason}"


class TestIn(BaseModel):
    actor: str = Field(min_length=2, max_length=255)


@router.post("/channels/{channel_id}/test")
def test_channel(channel_id: str, payload: TestIn = None,
                 org: models.Organization = Depends(auth.require_admin),
                 session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    row = session.get(models.NotificationChannel, channel_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "channel not found")
    code, error = deliver(row, "test", {"message": "Barad-dûr webhook test"})
    delivery = models.NotificationDelivery(
        org_id=org.id, channel_id=row.id, event="test",
        dedupe_key=f"test:{row.id}:{models.utcnow().isoformat()}",
        payload=json.dumps({"message": "webhook test"}), status=(
            "sent" if error is None else "failed"),
        http_status=code, error=error, created_at=models.utcnow())
    session.add(delivery)
    session.commit()
    return {"data": {"delivered": error is None, "http_status": code,
                     "error": error}}


class TickIn(BaseModel):
    actor: str = Field(default="notifier", min_length=2, max_length=255)


@router.post("/tick")
def tick(payload: TickIn = None,
         org: models.Organization = Depends(auth.require_admin),
         session: Session = Depends(get_session)):
    """Deliver `sla.breached` once per channel per day for breached findings."""
    payload = payload or TickIn()
    now = models.utcnow()
    day = now.date().isoformat()
    breached = [row for row in
                (session.query(models.Finding).filter_by(org_id=org.id).all())
                if row.sla_deadline is not None
                and auth_local.ensure_aware(row.sla_deadline) < now
                and row.status not in NON_OPEN]
    channels = (session.query(models.NotificationChannel)
                .filter_by(org_id=org.id, enabled=True).all())
    results = []
    for channel in channels:
        events = set(json.loads(channel.events or "[]"))
        if "sla.breached" not in events or not breached:
            continue
        dedupe = f"sla:{channel.id}:{day}"
        if session.query(models.NotificationDelivery).filter_by(
                org_id=org.id, dedupe_key=dedupe).first():
            results.append({"channel": channel.name, "result": "already_sent"})
            continue
        summary = {
            "date": day,
            "count": len(breached),
            "findings": [{"id": row.id, "title": row.title[:160],
                          "severity": row.severity,
                          "sla_deadline": row.sla_deadline.isoformat()}
                         for row in breached[:50]],
        }
        code, error = deliver(channel, "sla.breached", summary)
        session.add(models.NotificationDelivery(
            org_id=org.id, channel_id=channel.id, event="sla.breached",
            dedupe_key=dedupe, payload=json.dumps(summary),
            status="sent" if error is None else "failed",
            http_status=code, error=error, created_at=now))
        _audit_log(session, org.id, payload.actor, "notifications.sla_delivered",
                   "notification_channel", channel.id,
                   f"{len(breached)} breached, {'sent' if error is None else 'failed'}")
        results.append({"channel": channel.name,
                        "result": "sent" if error is None else "failed",
                        "count": len(breached), "error": error})
    session.commit()
    return {"data": {"breached": len(breached), "deliveries": results}}


@router.get("/deliveries")
def list_deliveries(limit: int = Query(default=50, ge=1, le=200),
                    org: models.Organization = Depends(auth.require_admin),
                    session: Session = Depends(get_session)):
    rows = (session.query(models.NotificationDelivery).filter_by(org_id=org.id)
            .order_by(models.NotificationDelivery.created_at.desc())
            .limit(limit).all())
    return {"data": [{"id": r.id, "channel_id": r.channel_id, "event": r.event,
                      "status": r.status, "http_status": r.http_status,
                      "error": r.error,
                      "created_at": r.created_at.isoformat()} for r in rows],
            "total": len(rows)}

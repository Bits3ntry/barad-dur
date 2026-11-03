"""BL-050: Jira bridge endpoints (links, outbox, webhook, reconciliation).

Contract:
  - Barad-dûr remains the source of truth for security findings.
  - Jira remains the source of truth for its own task workflow.
  - A ticket reaching a done status NEVER closes a finding; it flips the link
    to `verification_required` and the finding keeps its own lifecycle.
  - All outbound calls are queued in jira_outbox with a dedupe key, so a
    retry or a duplicate webhook cannot create duplicate issues.
"""
import hashlib
import hmac
import json

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, jira_client, models
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1/jira", tags=["jira"])

TERMINAL_STATUSES = {"done", "closed", "resolved", "completed", "fixed"}


def _link_data(row: models.JiraLink) -> dict:
    return {"id": row.id, "finding_id": row.finding_id,
            "project_key": row.project_key, "issue_key": row.issue_key,
            "issue_url": row.issue_url, "external_status": row.external_status,
            "external_assignee": row.external_assignee,
            "sync_state": row.sync_state, "last_error": row.last_error,
            "last_synced_at": row.last_synced_at.isoformat() if row.last_synced_at else None}


def _enqueue(session, org_id: str, link: models.JiraLink, action: str,
             payload: dict, dedupe_key: str) -> models.JiraOutbox:
    existing = (session.query(models.JiraOutbox)
                .filter_by(org_id=org_id, dedupe_key=dedupe_key).one_or_none())
    if existing is not None:
        return existing
    row = models.JiraOutbox(
        org_id=org_id, link_id=link.id, action=action,
        payload=json.dumps(payload, sort_keys=True), dedupe_key=dedupe_key,
        status="pending", attempts=0, created_at=models.utcnow())
    session.add(row)
    session.flush()
    return row


def _drain_one(session, org: models.Organization, item: models.JiraOutbox) -> dict:
    """Send one outbox item. Returns an outcome dict; failures stay pending."""
    link = session.get(models.JiraLink, item.link_id)
    payload = json.loads(item.payload)
    item.attempts += 1
    try:
        if item.action == "create":
            issue = jira_client.create_issue(**payload)
            key = issue.get("key")
            if not key:
                raise jira_client.JiraError("jira_create_missing_key")
            link.issue_key = key
            link.issue_url = f"{(jira_client._config()[0])}/browse/{key}"
            link.sync_state = "linked"
            issue_fields = jira_client.get_issue(key)
            link.external_status = (issue_fields.get("fields", {})
                                    .get("status", {}).get("name"))
            link.last_synced_at = models.utcnow()
        elif item.action == "update":
            jira_client.update_issue(link.issue_key, payload)
            link.sync_state = "linked"
            link.last_synced_at = models.utcnow()
        elif item.action == "transition":
            jira_client.transition_issue(link.issue_key, payload["to_status"])
            link.sync_state = "linked"
            link.last_synced_at = models.utcnow()
        else:
            raise jira_client.JiraError(f"unknown_action: {item.action}")
        item.status = "sent"
        item.sent_at = models.utcnow()
        item.last_error = None
        link.last_error = None
        outcome = {"id": item.id, "action": item.action, "result": "sent"}
    except jira_client.JiraError as exc:
        item.status = "failed"
        item.last_error = str(exc)[:500]
        link.last_error = str(exc)[:500]
        link.sync_state = "error"
        outcome = {"id": item.id, "action": item.action, "result": "failed",
                   "error": str(exc)[:200]}
    session.commit()
    return outcome


class LinkIn(BaseModel):
    finding_id: str
    project_key: str = Field(min_length=2, max_length=64)
    issue_type: str = "Task"
    assignee: str | None = None
    actor: str = Field(min_length=2, max_length=255)
    send_now: bool = True


@router.post("/links")
def create_link(payload: LinkIn = None,
                org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    finding = session.get(models.Finding, payload.finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    existing = (session.query(models.JiraLink)
                .filter_by(org_id=org.id, finding_id=finding.id).one_or_none())
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"finding already linked to {existing.issue_key or 'a pending issue'}")
    link = models.JiraLink(
        org_id=org.id, finding_id=finding.id, project_key=payload.project_key,
        sync_state="pending", created_at=models.utcnow(),
        updated_at=models.utcnow())
    session.add(link)
    session.flush()
    summary = finding.title or finding.rule_id or "Security finding"
    description = (f"Barad-dûr finding {finding.id}\n"
                   f"severity: {finding.severity}\n"
                   f"rule: {finding.rule_id or '-'}\n"
                   f"path: {finding.path or '-'}:{finding.line or '-'}\n"
                   f"project version: {finding.last_seen_version_id or '-'}\n"
                   "A Jira 'Done' does not remediate this finding: it needs "
                   "verification in Barad-dûr.")
    _enqueue(session, org.id, link, "create",
             {"project_key": payload.project_key, "summary": summary,
              "description": description, "issue_type": payload.issue_type,
              "assignee": payload.assignee},
             dedupe_key=f"create:{link.id}")
    _audit_log(session, org.id, payload.actor, "jira.link_created",
               "jira_link", link.id, payload.project_key)
    session.commit()
    outcome = None
    if payload.send_now and jira_client.configured():
        item = (session.query(models.JiraOutbox)
                .filter_by(org_id=org.id, link_id=link.id, status="pending")
                .order_by(models.JiraOutbox.created_at).first())
        if item is not None:
            outcome = _drain_one(session, org, item)
    session.refresh(link)
    return {"data": _link_data(link), "outcome": outcome,
            "jira_configured": jira_client.configured()}


@router.get("/links")
def list_links(sync_state: str | None = None,
               org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    query = session.query(models.JiraLink).filter_by(org_id=org.id)
    if sync_state:
        query = query.filter_by(sync_state=sync_state)
    rows = query.order_by(models.JiraLink.created_at.desc()).all()
    return {"data": [_link_data(r) for r in rows], "total": len(rows),
            "jira_configured": jira_client.configured()}


class SyncIn(BaseModel):
    actor: str = Field(min_length=2, max_length=255)
    assignee: str | None = None
    to_status: str | None = None


@router.post("/links/{link_id}/sync")
def sync_link(link_id: str, payload: SyncIn = None,
              org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session)):
    """Push permitted changes: assignee, and an explicit status transition.
    Barad-dûr never copies finding severity/status into Jira silently."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    link = session.get(models.JiraLink, link_id)
    if link is None or link.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "link not found")
    if not link.issue_key:
        raise HTTPException(status.HTTP_409_CONFLICT, "issue not created yet")
    if not jira_client.configured():
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "jira_not_configured")
    outcomes = []
    if payload.assignee:
        item = _enqueue(session, org.id, link, "update",
                        {"assignee": {"accountId": payload.assignee}},
                        dedupe_key=f"assignee:{link.id}:{payload.assignee}:"
                                   f"{len(payload.assignee)}")
        session.commit()
        outcomes.append(_drain_one(session, org, item))
    if payload.to_status:
        item = _enqueue(session, org.id, link, "transition",
                        {"to_status": payload.to_status},
                        dedupe_key=f"transition:{link.id}:{payload.to_status}")
        session.commit()
        outcomes.append(_drain_one(session, org, item))
    _audit_log(session, org.id, payload.actor, "jira.link_synced",
               "jira_link", link.id, json.dumps(outcomes, sort_keys=True)[:200])
    session.commit()
    session.refresh(link)
    return {"data": _link_data(link), "outcomes": outcomes}


class WebhookIn(BaseModel):
    issue_key: str
    status_name: str | None = None
    assignee: str | None = None
    actor: str | None = "jira-webhook"


@router.post("/webhook")
def webhook(request: Request, payload: WebhookIn = None,
            x_barad_secret: str | None = Header(default=None),
            session: Session = Depends(get_session)):
    """Receive Jira issue updates. Authenticated by a shared secret header;
    idempotent (repeated deliveries converge to the same state)."""
    import os

    expected = os.environ.get("JIRA_WEBHOOK_SECRET") or ""
    if not expected:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "webhook_secret_not_configured")
    if not x_barad_secret or not hmac.compare_digest(x_barad_secret, expected):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid webhook secret")
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    link = (session.query(models.JiraLink)
            .filter_by(issue_key=payload.issue_key).one_or_none())
    if link is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "issue not linked")
    changed = []
    if payload.status_name and payload.status_name != link.external_status:
        changed.append(f"status {link.external_status} -> {payload.status_name}")
        link.external_status = payload.status_name
        if payload.status_name.strip().lower() in TERMINAL_STATUSES:
            link.sync_state = "verification_required"
            changed.append("finding needs verification (Jira Done is not remediation)")
    if payload.assignee and payload.assignee != link.external_assignee:
        changed.append(f"assignee {link.external_assignee} -> {payload.assignee}")
        link.external_assignee = payload.assignee
    link.updated_at = models.utcnow()
    if changed:
        _audit_log(session, link.org_id, payload.actor or "jira-webhook",
                   "jira.webhook", "jira_link", link.id, "; ".join(changed)[:400])
    session.commit()
    return {"data": _link_data(link), "changed": changed}


class ReconcileIn(BaseModel):
    actor: str = Field(min_length=2, max_length=255)


@router.post("/reconcile")
def reconcile(payload: ReconcileIn = None,
              org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session)):
    """Pull each linked issue from Jira and converge local state. Never
    modifies the finding status."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if not jira_client.configured():
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "jira_not_configured")
    rows = (session.query(models.JiraLink)
            .filter_by(org_id=org.id).all())
    checked = drifted = errors = 0
    findings_to_verify = []
    for link in rows:
        if not link.issue_key:
            continue
        checked += 1
        try:
            issue = jira_client.get_issue(link.issue_key)
        except jira_client.JiraError as exc:
            errors += 1
            link.sync_state = "error"
            link.last_error = str(exc)[:500]
            continue
        fields = issue.get("fields", {})
        remote_status = (fields.get("status") or {}).get("name")
        remote_assignee = ((fields.get("assignee") or {}).get("displayName"))
        if remote_status != link.external_status or remote_assignee != link.external_assignee:
            drifted += 1
            _audit_log(session, org.id, payload.actor, "jira.drift_detected",
                       "jira_link", link.id,
                       f"{link.external_status} -> {remote_status}")
            if remote_status and remote_status.strip().lower() in TERMINAL_STATUSES:
                link.sync_state = "verification_required"
                findings_to_verify.append(link.finding_id)
        link.external_status = remote_status
        link.external_assignee = remote_assignee
        if link.sync_state != "verification_required":
            link.sync_state = "linked"
        link.last_synced_at = models.utcnow()
        link.last_error = None
    session.commit()
    return {"data": {"checked": checked, "drifted": drifted, "errors": errors,
                     "verification_required": findings_to_verify}}

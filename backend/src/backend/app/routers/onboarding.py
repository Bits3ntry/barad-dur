"""Onboarding: the organization profile, the first seats, and the two connections.

This router owns the ordered path from "first owner signed in" to "a workspace
someone can work in":

1. Organization details (name, logo, description, website).
2. Invite the team — email invitations with a single-use token, a role table,
   and optional teams that scope what a member can see.
3. Connect code — GitHub, GitLab or Gitea, **read-only**.
4. Connect tickets — Jira.

Two invariants hold across every endpoint here:

* **An invitation is a seat, not an email.** The row is the truth; the email is
  one delivery channel. With no SMTP the API answers with the single-use link so
  the owner can hand it over out of band, and says so instead of pretending the
  mail left.
* **A connection is read-only.** `access` is stored as "read" and nothing in
  this module ever issues a write to a provider: the probe is a GET of the
  authenticated identity. Cloning and analysing arrive later; pushing, editing
  and deleting never do.
"""
import base64
import json
import os
import secrets
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, mail, models, secrets as secret_store
from backend.app import auth_local
from backend.app.db import get_session
from backend.app.routers import accounts as accounts_router
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1/onboarding", tags=["onboarding"])
public_router = APIRouter(prefix="/api/v1/auth/invitations", tags=["onboarding"])

INVITE_TTL_DAYS = int(os.environ.get("INVITE_TTL_DAYS") or 7)
PROBE_TIMEOUT = float(os.environ.get("INTEGRATION_PROBE_TIMEOUT") or 8)

# The three roles an owner can hand out, in the vocabulary the console renders.
# Owner is absent on purpose: bootstrap assigns it, and a second owner is a
# transfer, not an invitation. The access lines are what this platform actually
# enforces — inventing a capability here would be a lie in an onboarding form.
ROLES = [
    {"value": "viewer", "label": "Viewer", "risk": "Low risk",
     "summary": "Read-only access to assigned resources",
     "access": "Reads findings, assets, dashboards and exposure history. "
               "Cannot change anything."},
    {"value": "analyst", "label": "Member", "risk": "High risk",
     "summary": "Standard member with read/write access to assigned resources",
     "access": "Writes findings, scope, assets and application records, and "
               "runs analysis. Cannot manage people, teams or integrations."},
    {"value": "admin", "label": "Administrator", "risk": "Full control",
     "summary": "Administrative access to most resources",
     "access": "Manages members, teams, grants and integrations and sees all "
               "data. Ownership transfer stays with the owner."},
]
ROLE_LABELS = {role["value"]: role["label"] for role in ROLES}
INVITABLE_ROLES = set(ROLE_LABELS)

SCM_PROVIDERS = {"github", "gitlab", "gitea"}
PROVIDER_LABELS = {"github": "GitHub", "gitlab": "GitLab", "gitea": "Gitea",
                   "jira": "Jira"}


# ── serialisation ────────────────────────────────────────────────────────────

def _iso(value: datetime | None) -> str | None:
    """SQLite hands back naive datetimes; Postgres does not. One shape on the wire."""
    if value is None:
        return None
    return auth_local.ensure_aware(value).isoformat()


def _org_data(row: models.Organization) -> dict:
    return {"id": row.id, "slug": row.slug, "name": row.name,
            "description": row.description, "website": row.website,
            "logo": row.logo,
            "created_at": _iso(row.created_at),
            "onboarding_completed_at": _iso(row.onboarding_completed_at)}


def _invitation_status(row: models.OrganizationInvitation) -> str:
    if row.accepted_at is not None:
        return "accepted"
    if row.revoked_at is not None:
        return "revoked"
    expires = auth_local.ensure_aware(row.expires_at)
    if expires is not None and expires <= models.utcnow():
        return "expired"
    return "pending"


def _invitation_data(row: models.OrganizationInvitation, team_name: str | None = None,
                     link: str | None = None) -> dict:
    data = {"id": row.id, "email": row.email, "role": row.role,
            "role_label": ROLE_LABELS.get(row.role, row.role),
            "team_id": row.team_id, "team": team_name,
            "display_name": row.display_name, "invited_by": row.invited_by,
            "status": _invitation_status(row),
            "expires_at": _iso(row.expires_at),
            "accepted_at": _iso(row.accepted_at),
            "last_sent_at": _iso(row.last_sent_at),
            "last_delivery": row.last_delivery,
            "created_at": _iso(row.created_at)}
    if link:
        data["invite_url"] = link
    return data


def _team_data(row: models.Team, members: int = 0) -> dict:
    return {"id": row.id, "name": row.name, "description": row.description,
            "members": members, "created_at": _iso(row.created_at)}


def _connection_data(row: models.IntegrationConnection) -> dict:
    """Never includes the credential, not even masked."""
    config = {}
    if row.config:
        try:
            config = json.loads(row.config)
        except json.JSONDecodeError:
            config = {}
    return {"id": row.id, "kind": row.kind, "provider": row.provider,
            "provider_label": PROVIDER_LABELS.get(row.provider, row.provider),
            "label": row.label, "base_url": row.base_url, "account": row.account,
            "access": row.access, "config": config,
            "verified_at": _iso(row.verified_at), "last_error": row.last_error,
            "created_at": _iso(row.created_at)}


# ── state ────────────────────────────────────────────────────────────────────

@router.get("")
def onboarding_state(org: models.Organization = Depends(auth.require_admin),
                     session: Session = Depends(get_session)):
    # One pass over team memberships; the per-team count is a GROUP BY the ORM
    # keeps portable across SQLite and Postgres.
    counts: dict[str, int] = {}
    for (team_id,) in session.query(models.TeamMember.team_id).filter_by(
            org_id=org.id).all():
        counts[team_id] = counts.get(team_id, 0) + 1
    teams = (session.query(models.Team).filter_by(org_id=org.id)
             .order_by(models.Team.name).all())
    members = (session.query(models.User).filter_by(org_id=org.id)
               .order_by(models.User.created_at).all())
    invitations = (session.query(models.OrganizationInvitation)
                   .filter_by(org_id=org.id)
                   .order_by(models.OrganizationInvitation.created_at.desc()).all())
    team_names = {row.id: row.name for row in teams}
    connections = (session.query(models.IntegrationConnection)
                   .filter_by(org_id=org.id)
                   .order_by(models.IntegrationConnection.created_at).all())
    return {"data": {
        "org": _org_data(org),
        "completed": org.onboarding_completed_at is not None,
        "roles": ROLES,
        "members": [{"id": row.id, "email": row.email,
                     "display_name": row.display_name, "role": row.role,
                     "role_label": ROLE_LABELS.get(row.role, row.role),
                     "status": row.status,
                     "last_login_at": _iso(row.last_login_at)} for row in members],
        "invitations": [_invitation_data(row, team_names.get(row.team_id))
                        for row in invitations],
        "teams": [_team_data(row, counts.get(row.id, 0)) for row in teams],
        "mail": {**mail.status(session), "key_source": secret_store.key_source(session)},
        "connections": {
            "scm": [_connection_data(row) for row in connections
                    if row.kind == "scm"],
            "tickets": [_connection_data(row) for row in connections
                        if row.kind == "tickets"],
        },
    }}


@router.post("/complete")
def complete_onboarding(actor: str = "onboarding",
                        org: models.Organization = Depends(auth.require_admin),
                        session: Session = Depends(get_session)):
    """Mark the walk-through done. Idempotent: re-running keeps the first date."""
    if org.onboarding_completed_at is None:
        org.onboarding_completed_at = models.utcnow()
        _audit_log(session, org.id, actor, "onboarding.completed", "organization",
                   org.id, "")
        session.commit()
    return {"data": {"completed": True,
                     "completed_at": _iso(org.onboarding_completed_at)}}


# ── teams ────────────────────────────────────────────────────────────────────

class TeamIn(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    description: str | None = Field(default=None, max_length=1000)
    actor: str = Field(default="onboarding", max_length=320)


@router.get("/teams")
def list_teams(org: models.Organization = Depends(auth.require_admin),
               session: Session = Depends(get_session)):
    counts: dict[str, int] = {}
    for (team_id,) in session.query(models.TeamMember.team_id).filter_by(
            org_id=org.id).all():
        counts[team_id] = counts.get(team_id, 0) + 1
    rows = (session.query(models.Team).filter_by(org_id=org.id)
            .order_by(models.Team.name).all())
    return {"data": [_team_data(row, counts.get(row.id, 0)) for row in rows],
            "total": len(rows)}


@router.post("/teams")
def create_team(payload: TeamIn = None,
                org: models.Organization = Depends(auth.require_admin),
                session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    name = payload.name.strip()
    existing = (session.query(models.Team)
                .filter_by(org_id=org.id, name=name).one_or_none())
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "a team with that name exists")
    row = models.Team(org_id=org.id, name=name,
                      description=(payload.description or "").strip() or None,
                      created_by=payload.actor, created_at=models.utcnow())
    session.add(row)
    session.flush()
    _audit_log(session, org.id, payload.actor, "onboarding.team_created", "team",
               row.id, name)
    session.commit()
    return {"data": _team_data(row, 0)}


# ── invitations ──────────────────────────────────────────────────────────────

def _console_base(request: Request) -> str:
    configured = (os.environ.get("PLATFORM_CONSOLE_URL") or "").rstrip("/")
    if configured:
        return configured
    return str(request.base_url).rstrip("/")


def _invite_link(request: Request, raw_token: str) -> str:
    return f"{_console_base(request)}/invite#token={raw_token}"


def _invite_body(org_name: str, role_label: str, link: str, expires: datetime) -> str:
    return (
        f"You have been invited to join {org_name} in Barad-dûr as {role_label}.\n\n"
        f"Accept the invitation and choose your password:\n{link}\n\n"
        f"The link works once and expires on "
        f"{expires.strftime('%Y-%m-%d %H:%M UTC')}.\n"
        "If you were not expecting this message, ignore it — the invitation "
        "can be revoked by the organization at any time.\n"
    )


def _deliver(session: Session, request: Request, org: models.Organization,
             row: models.OrganizationInvitation, raw_token: str) -> dict:
    link = _invite_link(request, raw_token)
    label = ROLE_LABELS.get(row.role) or row.role
    delivered, reason = mail.send(
        row.email, f"Join {org.name} on Barad-dûr",
        _invite_body(org.name, label, link, auth_local.ensure_aware(row.expires_at)),
        session=session)
    row.last_sent_at = models.utcnow()
    row.last_delivery = "email" if delivered else reason[:255]
    return {"channel": "email" if delivered else "manual_link",
            "sent": delivered, "reason": reason or None}


class InviteIn(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    role: str = Field(default="analyst", max_length=16)
    team_id: str | None = None
    display_name: str | None = Field(default=None, max_length=255)
    actor: str = Field(default="onboarding", max_length=320)


def _validate_invite(session: Session, org: models.Organization, payload: InviteIn):
    email = payload.email.strip().lower()
    if "@" not in email:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "that does not look like an email address")
    if payload.role not in INVITABLE_ROLES:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"role must be one of {sorted(INVITABLE_ROLES)}; ownership is not "
            "invited")
    if session.query(models.User).filter_by(org_id=org.id, email=email).first():
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "that person is already a member")
    team = None
    if payload.team_id:
        team = session.get(models.Team, payload.team_id)
        if team is None or team.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "team not found")
    return email, team


@router.get("/invitations")
def list_invitations(org: models.Organization = Depends(auth.require_admin),
                     session: Session = Depends(get_session)):
    team_names = {row.id: row.name for row in
                  session.query(models.Team).filter_by(org_id=org.id).all()}
    rows = (session.query(models.OrganizationInvitation)
            .filter_by(org_id=org.id)
            .order_by(models.OrganizationInvitation.created_at.desc()).all())
    return {"data": [_invitation_data(row, team_names.get(row.team_id))
                     for row in rows], "total": len(rows)}


@router.post("/invitations")
def invite_member(request: Request, payload: InviteIn = None,
                  org: models.Organization = Depends(auth.require_admin),
                  session: Session = Depends(get_session)):
    """Create or re-issue one seat. The link is returned only to the caller."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    email, team = _validate_invite(session, org, payload)
    raw_token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(days=INVITE_TTL_DAYS)

    row = (session.query(models.OrganizationInvitation)
           .filter_by(org_id=org.id, email=email).one_or_none())
    if row is None:
        row = models.OrganizationInvitation(
            org_id=org.id, email=email, created_at=models.utcnow())
        session.add(row)
    elif row.accepted_at is not None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "that invitation was already accepted")
    row.role = payload.role
    row.team_id = team.id if team is not None else None
    row.display_name = payload.display_name
    row.invited_by = payload.actor
    row.token_hash = auth_local.token_hash(raw_token)
    row.expires_at = expires
    row.revoked_at = None
    session.flush()

    delivery = _deliver(session, request, org, row, raw_token)
    _audit_log(session, org.id, payload.actor, "onboarding.invited", "invitation",
               row.id, f"{email} as {payload.role} via {delivery['channel']}")
    session.commit()
    return {"data": _invitation_data(row, team.name if team else None,
                                     link=_invite_link(request, raw_token)),
            "delivery": delivery}


class InviteActor(BaseModel):
    actor: str = Field(default="onboarding", max_length=320)


@router.post("/invitations/{invitation_id}/resend")
def resend_invitation(invitation_id: str, request: Request,
                      payload: InviteActor = None,
                      org: models.Organization = Depends(auth.require_admin),
                      session: Session = Depends(get_session)):
    """Rotate the token and deliver again; the previous link stops working."""
    payload = payload or InviteActor()
    row = session.get(models.OrganizationInvitation, invitation_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "invitation not found")
    if row.accepted_at is not None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "that invitation was already accepted")
    raw_token = secrets.token_urlsafe(32)
    row.token_hash = auth_local.token_hash(raw_token)
    row.expires_at = datetime.now(timezone.utc) + timedelta(days=INVITE_TTL_DAYS)
    row.revoked_at = None
    session.flush()
    delivery = _deliver(session, request, org, row, raw_token)
    _audit_log(session, org.id, payload.actor, "onboarding.invite_resent",
               "invitation", row.id, delivery["channel"])
    session.commit()
    team = session.get(models.Team, row.team_id) if row.team_id else None
    return {"data": _invitation_data(row, team.name if team else None,
                                     link=_invite_link(request, raw_token)),
            "delivery": delivery}


@router.post("/invitations/{invitation_id}/revoke")
def revoke_invitation(invitation_id: str, payload: InviteActor = None,
                      org: models.Organization = Depends(auth.require_admin),
                      session: Session = Depends(get_session)):
    payload = payload or InviteActor()
    row = session.get(models.OrganizationInvitation, invitation_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "invitation not found")
    if row.accepted_at is not None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "that invitation was already accepted")
    if row.revoked_at is None:
        row.revoked_at = models.utcnow()
        _audit_log(session, org.id, payload.actor, "onboarding.invite_revoked",
                   "invitation", row.id, row.email)
        session.commit()
    return {"data": _invitation_data(row)}


# ── public acceptance ────────────────────────────────────────────────────────

def _invite_by_token(session: Session, raw_token: str):
    if not raw_token:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "invitation not found")
    return (session.query(models.OrganizationInvitation)
            .filter_by(token_hash=auth_local.token_hash(raw_token)).one_or_none())


@public_router.get("/{token}")
def describe_invitation(token: str, session: Session = Depends(get_session)):
    """Public: what the accept screen needs, and nothing about the workspace's data."""
    row = _invite_by_token(session, token)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "invitation not found")
    org = session.get(models.Organization, row.org_id)
    row_status = _invitation_status(row)
    return {"data": {"org_name": org.name if org else "",
                     "org_slug": org.slug if org else "",
                     "email": row.email, "role": row.role,
                     "role_label": ROLE_LABELS.get(row.role, row.role),
                     "expires_at": _iso(row.expires_at),
                     "valid": row_status == "pending", "status": row_status}}


class AcceptIn(BaseModel):
    token: str = Field(min_length=8, max_length=512)
    password: str = Field(min_length=8, max_length=200)
    display_name: str | None = Field(default=None, max_length=255)


@public_router.post("/accept")
def accept_invitation(payload: AcceptIn = None,
                      session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    row = _invite_by_token(session, payload.token)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "invitation not found")
    row_status = _invitation_status(row)
    if row_status != "pending":
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"invitation is {row_status}")
    org = session.get(models.Organization, row.org_id)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "organization not found")
    if session.query(models.User).filter_by(org_id=org.id, email=row.email).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "that person is already a member")
    try:
        password_hash = auth_local.hash_password(payload.password)
    except auth_local.AuthError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))
    now = models.utcnow()
    user = models.User(org_id=org.id, email=row.email,
                       display_name=payload.display_name or row.display_name
                       or row.email,
                       role=row.role, password_hash=password_hash,
                       status="active", created_at=now, updated_at=now)
    session.add(user)
    session.flush()
    session.add(models.OrgMember(org_id=org.id, identity=user.email, role=row.role,
                                 added_by=row.invited_by or "invitation"))
    if row.team_id:
        session.add(models.TeamMember(org_id=org.id, team_id=row.team_id,
                                      user_id=user.id, added_at=now,
                                      added_by=row.invited_by or "invitation"))
    row.accepted_at = now
    _audit_log(session, org.id, user.email, "onboarding.invite_accepted", "user",
               user.id, f"{row.role} via invitation")
    session.commit()
    return {"data": accounts_router._user_data(user),
            "session": accounts_router._issue_session(session, user)}


# ── connections (code and tickets) ───────────────────────────────────────────

class ConnectionIn(BaseModel):
    kind: str = Field(default="scm", max_length=16)
    provider: str = Field(min_length=2, max_length=32)
    base_url: str = Field(default="", max_length=255)
    token: str = Field(min_length=4, max_length=4096)
    label: str | None = Field(default=None, max_length=128)
    account: str | None = Field(default=None, max_length=255)
    project_key: str | None = Field(default=None, max_length=64)
    actor: str = Field(default="onboarding", max_length=320)


def _default_base(kind: str, provider: str) -> str:
    if provider == "github":
        return "https://api.github.com"
    if provider == "gitlab":
        return "https://gitlab.com"
    return ""


def _http_json(url: str, headers: dict) -> tuple[bool, dict | str]:
    request = urllib.request.Request(url, headers={"Accept": "application/json",
                                                   **headers})
    try:
        with urllib.request.urlopen(request, timeout=PROBE_TIMEOUT) as response:
            return True, json.loads(response.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode()[:200]
        except OSError:
            pass
        return False, f"http_{exc.code}: {detail}".strip()
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return False, f"unreachable: {type(exc).__name__}: {exc}"[:300]


def _probe(provider: str, base_url: str, token: str, account: str | None,
           project_key: str | None) -> tuple[bool, dict | str]:
    """Read the authenticated identity. Every call here is a GET on purpose."""
    base = (base_url or "").rstrip("/")
    if provider == "github":
        ok, body = _http_json(f"{base or 'https://api.github.com'}/user",
                              {"Authorization": f"Bearer {token}",
                               "X-GitHub-Api-Version": "2022-11-28"})
        if not ok:
            return False, body
        return True, {"account": body.get("login") or "", "detail":
                      "authenticated; repositories likely readable"}
    if provider == "gitlab":
        api = base or "https://gitlab.com"
        api = api if api.endswith("/api/v4") else f"{api}/api/v4"
        ok, body = _http_json(f"{api}/user", {"PRIVATE-TOKEN": token})
        if not ok:
            return False, body
        return True, {"account": body.get("username") or body.get("name") or "",
                      "detail": "authenticated"}
    if provider == "gitea":
        if not base:
            return False, "base_url is required for Gitea"
        ok, body = _http_json(f"{base}/api/v1/user",
                              {"Authorization": f"token {token}"})
        if not ok:
            return False, body
        return True, {"account": body.get("login") or body.get("full_name") or "",
                      "detail": "authenticated"}
    if provider == "jira":
        if not base:
            return False, "base_url is required for Jira"
        if not account:
            return False, "account is required for Jira (the email that owns the token)"
        basic = base64.b64encode(f"{account}:{token}".encode()).decode()
        ok, body = _http_json(f"{base}/rest/api/2/myself",
                              {"Authorization": f"Basic {basic}"})
        if not ok:
            return False, body
        detail = f"authenticated as {body.get('displayName') or body.get('name')}"
        if project_key:
            ok_project, project = _http_json(
                f"{base}/rest/api/2/project/{project_key}",
                {"Authorization": f"Basic {basic}"})
            if not ok_project:
                return False, f"project {project_key}: {project}"
            detail += f"; project {project.get('key')} readable"
        return True, {"account": body.get("emailAddress") or account,
                      "detail": detail}
    return False, f"unsupported provider {provider}"


@router.get("/connections")
def list_connections(org: models.Organization = Depends(auth.require_admin),
                     session: Session = Depends(get_session)):
    rows = (session.query(models.IntegrationConnection)
            .filter_by(org_id=org.id)
            .order_by(models.IntegrationConnection.created_at).all())
    return {"data": {"scm": [_connection_data(row) for row in rows
                             if row.kind == "scm"],
                     "tickets": [_connection_data(row) for row in rows
                                 if row.kind == "tickets"]}}


@router.post("/connections")
def create_connection(payload: ConnectionIn = None,
                      org: models.Organization = Depends(auth.require_admin),
                      session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    kind = payload.kind.strip().lower()
    provider = payload.provider.strip().lower()
    if kind not in {"scm", "tickets"}:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "kind must be 'scm' or 'tickets'")
    if kind == "scm" and provider not in SCM_PROVIDERS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"provider must be one of {sorted(SCM_PROVIDERS)}")
    if kind == "tickets" and provider != "jira":
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "tickets currently supports Jira")
    base_url = (payload.base_url or "").strip().rstrip("/")
    if base_url and not base_url.startswith(("http://", "https://")):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "base_url must start with http:// or https://")
    if kind == "tickets" and not base_url:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "base_url is required for Jira")
    base_url = base_url or _default_base(kind, provider)

    duplicate = (session.query(models.IntegrationConnection)
                 .filter_by(org_id=org.id, kind=kind, provider=provider,
                            base_url=base_url).one_or_none())
    if duplicate is not None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "that provider is already connected; verify or remove "
                            "the existing connection")

    verified, outcome = _probe(provider, base_url, payload.token,
                               payload.account, payload.project_key)
    if not verified:
        # Store nothing we could not prove: an unverified credential is a
        # liability dressed as configuration.
        raise HTTPException(status.HTTP_502_BAD_GATEWAY,
                            f"connection not verified: {outcome}")
    detail = outcome if isinstance(outcome, dict) else {}

    row = models.IntegrationConnection(
        org_id=org.id, kind=kind, provider=provider, base_url=base_url,
        label=payload.label or PROVIDER_LABELS.get(provider, provider),
        account=(detail.get("account") or payload.account or "")[:255] or None,
        secret_cipher=secret_store.seal(session, payload.token),
        config=json.dumps({"project_key": payload.project_key}
                          if payload.project_key else {}),
        access="read", verified_at=models.utcnow(),
        last_error=None, created_by=payload.actor, created_at=models.utcnow())
    session.add(row)
    session.flush()
    _audit_log(session, org.id, payload.actor, "onboarding.connected",
               "integration_connection", row.id,
               f"{kind}:{provider} read-only as {row.account or 'unknown'}")
    session.commit()
    return {"data": _connection_data(row), "detail": detail.get("detail")}


@router.post("/connections/{connection_id}/verify")
def verify_connection(connection_id: str, payload: InviteActor = None,
                      org: models.Organization = Depends(auth.require_admin),
                      session: Session = Depends(get_session)):
    payload = payload or InviteActor()
    row = session.get(models.IntegrationConnection, connection_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "connection not found")
    try:
        token = secret_store.open_sealed(session, row.secret_cipher)
    except ValueError as exc:
        row.last_error = str(exc)
        session.commit()
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc))
    config = json.loads(row.config) if row.config else {}
    verified, outcome = _probe(row.provider, row.base_url, token, row.account,
                               config.get("project_key"))
    if verified:
        detail_row = outcome if isinstance(outcome, dict) else {}
        row.verified_at = models.utcnow()
        row.last_error = None
        row.account = (detail_row.get("account") or row.account or "")[:255] or None
        detail = detail_row.get("detail")
    else:
        row.verified_at = None
        row.last_error = str(outcome)[:500]
        detail = None
    _audit_log(session, org.id, payload.actor,
               "onboarding.connection_verified" if verified
               else "onboarding.connection_verify_failed",
               "integration_connection", row.id, row.last_error or "ok")
    session.commit()
    return {"data": _connection_data(row), "verified": verified,
            "detail": detail}


@router.post("/connections/{connection_id}/remove")
def remove_connection(connection_id: str, payload: InviteActor = None,
                      org: models.Organization = Depends(auth.require_admin),
                      session: Session = Depends(get_session)):
    payload = payload or InviteActor()
    row = session.get(models.IntegrationConnection, connection_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "connection not found")
    _audit_log(session, org.id, payload.actor, "onboarding.connection_removed",
               "integration_connection", row.id,
               f"{row.kind}:{row.provider} {row.base_url}")
    session.delete(row)
    session.commit()
    return {"data": {"id": connection_id, "removed": True}}


@router.get("/connections/{connection_id}/repositories")
def list_connection_repositories(connection_id: str,
                                 org: models.Organization = Depends(auth.require_admin),
                                 session: Session = Depends(get_session)):
    """Read-only listing of what the token can see, for the inventory picker."""
    from backend.app import integrations, scm_client

    row = session.get(models.IntegrationConnection, connection_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "connection not found")
    if row.kind != "scm":
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "only code hosts list repositories")
    creds = integrations.find(session, org.id, "scm", provider=row.provider,
                              base_url=row.base_url)
    if creds is None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "the stored credential cannot be read; reconnect the host")
    try:
        rows = scm_client.list_repositories(row.provider, creds)
    except scm_client.ScmError as exc:
        raise HTTPException(exc.status_code or status.HTTP_502_BAD_GATEWAY,
                            str(exc)) from None
    return {"data": rows, "total": len(rows), "provider": row.provider}

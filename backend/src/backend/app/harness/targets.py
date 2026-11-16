"""One place that answers "may we touch this host?".

The router, the gates and the sibling probe all ask the same question, so they ask the
same code. A second implementation is how two of them start disagreeing.
"""

from __future__ import annotations

from datetime import timezone
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from backend.app import models


def aware(value):
    """SQLite hands back naive datetimes; `models.utcnow()` is aware."""
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def authorized_grant(session: Session, org: models.Organization, host: str):
    """The active, unexpired grant that covers `host`, or None."""
    if not host:
        return None
    host = host.lower()
    now = models.utcnow()
    for grant in (session.query(models.ScanGrant)
                  .filter_by(org_id=org.id, status="active").all()):
        expires = aware(grant.valid_until)
        if expires is not None and expires < now:
            continue
        for target in grant.targets:
            value = (target.target_value or "").strip().lower()
            if value.startswith("*.") and (host == value[2:] or host.endswith(value[1:])):
                return grant
            if "://" in value and urlsplit(value).hostname == host:
                return grant
            if value == host:
                return grant
    return None


def host_of(locator: str | None) -> str | None:
    if not locator:
        return None
    value = locator.strip()
    if value.startswith(("http://", "https://")):
        return urlsplit(value).hostname
    if "." in value and "/" not in value and ":" not in value:
        return value.lower()
    return None

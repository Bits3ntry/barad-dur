"""The human key: what a person's decision does to one finding.

Two axes, never one. `evidence_level` is proof — the machine raises it by
reproducing something, and nobody can claim it by clicking. `triage_status` is the
decision — a person's alone, and the only thing that puts a claim into the counted
posture. This module is the single place that writes the decision, so a run's
triage and a cycle's ledger cannot drift into two different vocabularies.
"""
from fastapi import HTTPException, status as http_status
from sqlalchemy.orm import Session

from backend.app import models

# decision → (triage_status, status). `validate` is the only one that turns a
# claim into a fact about a host, so it is the only one that attaches an asset.
DECISIONS = {"validate": ("triaged", "acknowledged"),
             "dismiss": ("rejected", "false_positive"),
             "accept_risk": ("accepted", "accepted_risk")}


def asset_for_claim(session: Session, org: models.Organization,
                    finding: models.Finding) -> models.Asset | None:
    """The asset a claim names, resolved from the location it reported.

    Ingest deliberately attaches nothing: an unclaimed host is the normal case in
    this estate, and a scanner is not the authority on what we own. Promotion
    resolves the same way ingest does, so the two never disagree about which host a
    finding pointed at.
    """
    if finding.asset_id:
        return session.get(models.Asset, finding.asset_id)
    where = (finding.url or "").strip().lower()
    if not where:
        return None
    host = where.split("//")[-1].split("/")[0] if "//" in where else where.split("/")[0]
    for candidate in (host, where):
        if not candidate:
            continue
        asset = (session.query(models.Asset)
                 .filter(models.Asset.org_id == org.id,
                         models.Asset.value == candidate).one_or_none())
        if asset is not None:
            return asset
    for row in (session.query(models.Asset)
                .filter(models.Asset.org_id == org.id).all()):
        if row.value and where.startswith(row.value.lower()):
            return row
    return None


def apply(session: Session, org: models.Organization, finding: models.Finding,
          decision: str, actor: str, reason: str | None = None) -> dict:
    """Apply one human decision. Returns what changed, for the caller's timeline."""
    if decision not in DECISIONS:
        raise HTTPException(http_status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"decision must be one of {sorted(DECISIONS)}")
    triage_verdict, status_value = DECISIONS[decision]
    finding.status = status_value
    finding.triage_status = triage_verdict
    finding.triaged_by = actor
    finding.triaged_at = models.utcnow()
    finding.triage_note = (reason or None)
    attached = None
    if decision == "validate" and finding.asset_id is None:
        asset = asset_for_claim(session, org, finding)
        if asset is not None:
            finding.asset_id = asset.id
            if finding.project_id is None:
                finding.project_id = asset.project_id
            attached = asset.id
    return {"decision": decision, "status": finding.status,
            "triage_status": finding.triage_status, "attached_asset": attached}

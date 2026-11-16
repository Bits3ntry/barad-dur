"""One hand-written claim, recorded the same way whatever door it came through.

A pentest report, a bug-bounty submission and an analyst's note are the same act:
somebody writes down a weakness with what it is, where it lives, how it is reached
and what proves it. The row starts as a claim (`triage_status = new`) and lands in a
cycle's ledger only when the caller names one — so the cycle screen and
`POST /findings/record` cannot drift into two different notions of "a record".
"""
import hashlib

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import models

HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}

# The origin a cycle writes on the rows it holds. `origin` is the "who said so"
# axis: a claim from a pentest is not a manual note somebody typed, and the
# findings screen filters on exactly these values.
ORIGIN_BY_KIND = {
    "pentest_external": "pentest-external",
    "pentest_internal": "pentest-internal",
    "ai_redteam": "shauron-ai",
}

CLAIM_KINDS = {"vulnerability", "secret", "misconfiguration", "code-weakness"}


class ClaimIn(BaseModel):
    """A vulnerability somebody wrote down.

    It is a claim whoever produced it — tool or person — so `triage_status` starts
    at `new`: the decision is a separate, audited act, and `evidence_level` is the
    only thing a person may set about proof.
    """

    title: str = Field(min_length=1, max_length=1024)
    kind: str = Field(default="vulnerability", max_length=32)
    vector: str | None = Field(default=None, max_length=32)
    severity: str | None = Field(default=None, max_length=32)
    description: str | None = Field(default=None, max_length=20000)
    url: str | None = Field(default=None, max_length=1024)
    asset_id: str | None = None
    project_id: str | None = None
    # The slug form, because a person reading the address has a slug in hand and
    # a form should not make them resolve an id first.
    project: str | None = Field(default=None, max_length=128)
    # The build the claim was seen in. A pentest against `aurea 1.4.0` is not the
    # same claim as one against `main`, and without this the row could not say
    # where it lives — only which product it belongs to.
    version_id: str | None = None
    cycle_id: str | None = None
    evidence_level: str = Field(default="observed", max_length=16)
    actor: str = Field(default="console", max_length=255)
    # ── the record: what it is, where it lives, how it is reached, what proves it ──
    cwe: str | None = Field(default=None, max_length=64)
    impact: str | None = Field(default=None, max_length=20000)
    reproduction: str | None = Field(default=None, max_length=20000)
    product_component_id: str | None = None
    http_method: str | None = Field(default=None, max_length=16)
    endpoint: str | None = Field(default=None, max_length=2048)
    auth_required: bool | None = None
    auth_profile_id: str | None = None
    expected_result: str | None = Field(default=None, max_length=20000)
    observed_result: str | None = Field(default=None, max_length=20000)
    validation_output: str | None = Field(default=None, max_length=20000)
    proof_request: str | None = Field(default=None, max_length=200000)
    proof_response: str | None = Field(default=None, max_length=200000)


def record_claim(session: Session, org, payload: ClaimIn, cycle=None):
    """Validate, dedupe and store one claim. Returns `(finding, created)`.

    Every reference the payload names is resolved inside the organization, because
    an id from another tenant must read as missing, not as found. The fingerprint is
    what makes recording the same report twice answer "already known" instead of
    minting a second row.
    """
    asset = None
    if payload.asset_id:
        asset = session.get(models.Asset, payload.asset_id)
        if asset is None or asset.org_id != org.id:
            raise ValueError("asset not found")
    if payload.http_method and payload.http_method.upper() not in HTTP_METHODS:
        raise ValueError(f"http_method must be one of {sorted(HTTP_METHODS)}")
    if payload.evidence_level not in models.EVIDENCE_LEVELS:
        raise ValueError(f"evidence_level must be one of {sorted(models.EVIDENCE_LEVELS)}")
    auth_profile = None
    if payload.auth_profile_id:
        auth_profile = session.get(models.AuthProfile, payload.auth_profile_id)
        if auth_profile is None or auth_profile.org_id != org.id:
            raise ValueError("auth profile not found")
    product = None
    if payload.product_component_id:
        product = session.get(models.ApplicationComponent, payload.product_component_id)
        if product is None or product.org_id != org.id:
            raise ValueError("product component not found")
    version_row = None
    if payload.version_id:
        version_row = session.get(models.ProjectVersion, payload.version_id)
        if version_row is None:
            raise ValueError("version not found")
        version_project = session.get(models.Project, version_row.project_id)
        if version_project is None or version_project.org_id != org.id:
            raise ValueError("version not found")
    project_id = payload.project_id or (version_row.project_id if version_row else None)
    if payload.project:
        named = (session.query(models.Project)
                 .filter_by(org_id=org.id, slug=payload.project).one_or_none())
        if named is None:
            raise ValueError("project not found")
        project_id = named.id
    if project_id:
        project = session.get(models.Project, project_id)
        if project is None or project.org_id != org.id:
            raise ValueError("project not found")
    elif asset is not None:
        project_id = asset.project_id

    # The identity of a hand-written claim: what it is, where it was seen, and —
    # when there is one — the owner. Recording the same report twice answers
    # `created: false` instead of minting a second row. The same weakness on two
    # endpoints is two findings: the endpoint is part of the identity.
    owner = project_id or (asset.value if asset is not None else
                           (f"cycle:{cycle.id}" if cycle is not None else f"org:{org.id}"))
    fingerprint = hashlib.sha256(
        f"{org.id}|{owner}|{payload.kind}|{payload.title.strip().lower()}|"
        f"{(payload.url or '').strip()}|{(payload.endpoint or '').strip()}".encode()
    ).hexdigest()
    existing = (session.query(models.Finding)
                .filter_by(org_id=org.id, fingerprint=fingerprint).one_or_none())
    if existing is not None:
        return existing, False

    finding = models.Finding(
        org_id=org.id, project_id=project_id, asset_id=asset.id if asset else None,
        kind=payload.kind, vector=payload.vector, fingerprint=fingerprint,
        source="manual",
        origin=ORIGIN_BY_KIND.get(getattr(cycle, "kind", None), "manual"),
        title=payload.title.strip(),
        detail=payload.description, severity=payload.severity,
        url=payload.url, status="open", evidence_level=payload.evidence_level,
        triage_status="new", cwe=payload.cwe, impact=payload.impact,
        reproduction=payload.reproduction,
        product_component_id=product.id if product else None,
        http_method=(payload.http_method or "").upper() or None,
        endpoint=payload.endpoint,
        auth_required=payload.auth_required,
        auth_profile_id=auth_profile.id if auth_profile else None,
        expected_result=payload.expected_result,
        observed_result=payload.observed_result,
        validation_output=payload.validation_output,
        proof_request=payload.proof_request,
        proof_response=payload.proof_response,
        last_seen_version_id=version_row.id if version_row else None)
    session.add(finding)
    session.flush()
    if cycle is not None:
        session.add(models.CycleFinding(
            org_id=org.id, cycle_id=cycle.id, finding_id=finding.id, source="manual"))
    return finding, True

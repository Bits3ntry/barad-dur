"""Gates: the only thing that can promote a candidate to a finding.

A gate is a callable that answers "did this survive?". Gates compose by short-circuit and
an exception is a refusal, never a pass. The chain never asks a model for permission:
each stage checks a fact (evidence present, host authorized, request replayed).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from backend.app import models
from backend.app.harness import evidence as evidence_mod
from backend.app.harness import targets


@dataclass
class GateContext:
    session: Session
    org: models.Organization
    candidate: models.Candidate
    evidence: list = field(default_factory=list)
    #: Injected by the caller: `replay(finding_id, target, expect) -> dict`.
    #: The harness never imports a router; the router hands it the capability.
    replay: Callable | None = None
    #: Injected by the caller: `sibling(finding_id, label_a, label_b, owner_marker)`.
    sibling: Callable | None = None


@dataclass
class GateVerdict:
    confirmed: bool
    reason: str
    stage: str = ""
    evidence_ref: str | None = None
    cost_usd: float | None = None

    @property
    def skipped(self) -> bool:
        return self.reason.startswith("skipped:")


Gate = Callable[[GateContext], GateVerdict]


def _host_of(items) -> str | None:
    for item in items:
        locator = item.locator or ""
        if locator.startswith(("http://", "https://")):
            return urlsplit(locator).hostname
        if locator and "." in locator and "/" not in locator and ":" not in locator:
            return locator.lower()
    return None


def _grant_for_host(session: Session, org: models.Organization, host: str):
    return targets.authorized_grant(session, org, host)


def evidence_present(ctx: GateContext) -> GateVerdict:
    if not ctx.evidence:
        return GateVerdict(False, "no evidence attached: a candidate without evidence is "
                                  "an assumption", "evidence_present")
    if not evidence_mod.confirmable(ctx.evidence):
        return GateVerdict(False, "no observation with a locator: an assumption cannot "
                                  "close a claim", "evidence_present")
    return GateVerdict(True, f"{len(ctx.evidence)} evidence item(s), at least one "
                             "observation with a locator", "evidence_present")


def authorized_target(ctx: GateContext) -> GateVerdict:
    host = _host_of(ctx.evidence)
    if not host:
        return GateVerdict(False, "the evidence does not name a host", "authorized_target")
    grant = _grant_for_host(ctx.session, ctx.org, host)
    if grant is not None:
        return GateVerdict(True, f"{host} covered by grant {grant.id} ({grant.level})",
                           "authorized_target", evidence_ref=grant.id)
    # An autonomous run's authorization is the mission the operator approved: it
    # names the targets and the capability, and it is the reason the agent was
    # allowed to send the request in the first place. Demanding a separate grant
    # here made every agent candidate unconfirmable, which is the opposite of what
    # the envelope is for.
    mission = _mission_for_host(ctx.session, ctx.org, ctx.candidate.mission_id, host)
    if mission is not None:
        return GateVerdict(True, f"{host} covered by mission {mission.id[:8]} "
                                 f"({mission.capability}, approved by {mission.approved_by})",
                           "authorized_target", evidence_ref=mission.id)
    return GateVerdict(False, f"{host} is not covered by an active grant or mission",
                       "authorized_target")


def _request_of(candidate) -> dict | None:
    """The chain step a candidate carries, when it came from a field agent."""
    try:
        payload = json.loads(candidate.evidence or "{}")
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    request = payload.get("request")
    return request if isinstance(request, dict) else None


def _mission_for_host(session, org, mission_id, host):
    """The approved mission whose envelope covers `host`, if any."""
    if not mission_id:
        return None
    mission = session.get(models.AgentMission, mission_id)
    if mission is None or mission.org_id != org.id:
        return None
    if mission.status not in {"approved", "running", "done"}:
        return None
    host = (host or "").lower()
    for target in json.loads(mission.targets or "[]"):
        value = str(target.get("value") or "").lower()
        if not value:
            continue
        if value.startswith(("http://", "https://")):
            value = value.split("//", 1)[1].split("/")[0]
        value = value.split(":")[0]
        if value == host or host.endswith("." + value):
            return mission
    return None


def replay(ctx: GateContext) -> GateVerdict:
    if ctx.replay is None:
        return GateVerdict(False, "skipped: no replay capability was provided",
                           "replay")
    finding_id = ctx.candidate.finding_id
    request = _request_of(ctx.candidate)
    if not finding_id and request is None:
        return GateVerdict(False, "the candidate points at no finding and carries no "
                                  "request, so there is nothing to re-send", "replay")
    result = ctx.replay(finding_id=finding_id, target=None, expect=None,
                        request=request) or {}
    state = result.get("state")
    if state == "blocked":
        return GateVerdict(False, "replay blocked: " + ", ".join(result.get("missing") or []),
                           "replay")
    if state in {"reproduced", "observed"}:
        return GateVerdict(True, f"replay answered {result.get('response', {}).get('status')}"
                                 f" ({state})", "replay",
                           evidence_ref=(result.get("artifact") or {}).get("body_sha256_16"))
    return GateVerdict(False, f"replay state {state}", "replay")


def expect_match(ctx: GateContext) -> GateVerdict:
    marker = None
    try:
        payload = json.loads(ctx.candidate.evidence or "{}")
        marker = payload.get("expect") if isinstance(payload, dict) else None
    except ValueError:
        marker = None
    if not marker:
        return GateVerdict(False, "skipped: no expect marker on this candidate",
                           "expect_match")
    if ctx.replay is None or not ctx.candidate.finding_id:
        return GateVerdict(False, "no replay available to compare against", "expect_match")
    result = ctx.replay(finding_id=ctx.candidate.finding_id, target=None, expect=marker) or {}
    if result.get("state") == "reproduced":
        return GateVerdict(True, f"marker {marker!r} present in the response",
                           "expect_match")
    return GateVerdict(False, f"marker {marker!r} absent: {result.get('state')}",
                       "expect_match")


def sibling_access(ctx: GateContext) -> GateVerdict:
    """The only stage that can prove an authorization bypass.

    It needs two principals on the grant and a marker that belongs to A. Without the
    marker there is no proof, only a suspicion, and a suspicion must not confirm.
    """
    if ctx.sibling is None:
        return GateVerdict(False, "skipped: no sibling capability was provided",
                           "sibling_access")
    try:
        payload = json.loads(ctx.candidate.evidence or "{}")
    except ValueError:
        payload = {}
    labels = payload.get("identities") if isinstance(payload, dict) else None
    if not isinstance(labels, list) or len(labels) != 2:
        return GateVerdict(False, "skipped: no identity pair declared on this candidate",
                           "sibling_access")
    marker = payload.get("owner_marker") if isinstance(payload, dict) else None
    result = ctx.sibling(finding_id=ctx.candidate.finding_id, label_a=labels[0],
                         label_b=labels[1], owner_marker=marker) or {}
    state = result.get("state")
    if state == "leak":
        return GateVerdict(True, result.get("reason") or "identity B received A's record",
                           "sibling_access",
                           evidence_ref=(result.get("b") or {}).get("sha256_16"))
    return GateVerdict(False, f"sibling state {state}: {result.get('reason')}",
                       "sibling_access")


DEFAULT_STAGES: tuple[Gate, ...] = (evidence_present, authorized_target, replay,
                                    expect_match)


def compose_gates(*stages: Gate) -> Gate:
    """Run stages in order, stopping at the first refusal. An exception is a refusal."""
    def run(ctx: GateContext) -> GateVerdict:
        last = GateVerdict(True, "no stages")
        for stage in stages:
            try:
                verdict = stage(ctx)
            except Exception as error:  # a gate that cannot answer must not pass
                return GateVerdict(False, f"{stage.__name__} raised "
                                          f"{type(error).__name__}: {error}",
                                   stage.__name__)
            verdict.stage = verdict.stage or stage.__name__
            if not verdict.confirmed and not verdict.skipped:
                return verdict
            last = verdict
        return GateVerdict(True, last.reason, "compose")
    return run


def run_chain(session: Session, org: models.Organization, candidate: models.Candidate,
              *, replay: Callable | None = None, sibling: Callable | None = None,
              stages: tuple[Gate, ...] = DEFAULT_STAGES) -> dict:
    """Persist one `gate_runs` row per stage and settle the candidate's state."""
    ctx = GateContext(session=session, org=org, candidate=candidate,
                      evidence=evidence_mod.normalize(candidate.evidence),
                      replay=replay, sibling=sibling)
    verdicts = []
    for stage in stages:
        try:
            verdict = stage(ctx)
        except Exception as error:
            verdict = GateVerdict(False, f"{stage.__name__} raised "
                                         f"{type(error).__name__}: {error}",
                                  stage.__name__)
        verdict.stage = verdict.stage or stage.__name__
        session.add(models.GateRun(org_id=org.id, candidate_id=candidate.id,
                                   stage=verdict.stage,
                                   verdict="confirmed" if verdict.confirmed else
                                           ("skipped" if verdict.skipped else "refuted"),
                                   reason=verdict.reason,
                                   evidence_ref=verdict.evidence_ref,
                                   cost_usd=verdict.cost_usd))
        verdicts.append(verdict)
        if not verdict.confirmed and not verdict.skipped:
            candidate.state = "refuted"
            session.flush()
            return {"state": "refuted", "failed_at": verdict.stage,
                    "reason": verdict.reason,
                    "stages": [{"stage": v.stage, "confirmed": v.confirmed,
                                "reason": v.reason} for v in verdicts]}
    confirmed = all(v.confirmed or v.skipped for v in verdicts) and any(
        v.confirmed for v in verdicts)
    candidate.state = "validated" if confirmed else "proposed"
    session.flush()
    return {"state": candidate.state,
            "stages": [{"stage": v.stage, "confirmed": v.confirmed, "reason": v.reason}
                       for v in verdicts]}

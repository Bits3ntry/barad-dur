# Barad-dûr ↔ Shauron scanner contract

This document used to carry a v0 draft of the contract. **The contract now lives in
the Shauron repository**, which is its source of truth:

    ../shauron/CONTRACT.md      the envelopes: barad-ticket-v1, barad-evidence-v1,
                                barad-event-v1, and the invariants a receiver must refuse
    ../shauron/DESIGN.md        how a scan works: jobs, timeline, revival,
                                permissions, deadlines
    ../shauron/ARCHITECTURE.md  how the scanner is built and shipped
    ../shauron/contract/        the JSON Schemas, versioned, plus fixtures

Two products, one envelope. Barad-dûr mints and signs a **ticket**; Shauron
verifies it offline with the public key, executes inside it, and publishes
**events** and **evidence** keyed by `ticket_id`.

## What this repository implements (v01)

- `POST /api/v1/scans` — resolves an action into tasks, authorizes it **once**
  (grant for console work, repository binding for CI/CLI work), signs an Ed25519
  ticket and delivers it to a daemon.
- `GET /api/v1/scans/actions` — the closed catalog the console offers.
- `GET /api/v1/scans/key` — the public half of the signing key.
- `GET /api/v1/scans`, `GET /api/v1/scans/{id}`, `.../timeline` — the flow and its
  append-only history, with both clocks.
- `POST /api/v1/scans/{id}/events`, `.../evidence` — executor routes, authenticated
  with the ticket's own `upload_token`, never an organization API key.
- `POST /api/v1/scans/{id}/cancel` — a human instruction, not a policy verdict.
- `POST /api/v1/scans/sweep` — declares silent flows abandoned; idempotent, safe
  from cron.

`SUPPORTED_CONTRACT` in `routers/scans.py` is pinned to `shauron/VERSION`, and a
test fails when the two drift: a format change must fail a build, never a scan at
3am.

## The one rule worth repeating

A grant authorizes the platform to act **alone** on a target. CI and laptop runs
push evidence about code the caller already holds, so they need no grant; the
console button does. Revoking a grant does not stop a run in flight — it governs
the next ticket, and the running flow is annotated instead of killed. Cancelling
is a separate act: that one does stop it.

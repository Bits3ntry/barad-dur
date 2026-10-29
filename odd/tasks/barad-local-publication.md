# Barad local publication setup

Local CLI-only workflow for publishing external repository scan results without modifying scan targets.
The feature is security-sensitive because it loads runtime integration credentials.

## Specs

S1. "dejame todo armado en local para solo tener que poner los secrets y demas.... ten en cuenta que por norma general usaremos .env no?"

S2. "si lo ejecuto en local es decir desde mi pc apuntnando a otro repo no quiero tocar nada del otro repo, no estamos configurando la action"

## Tasks

- T1 [S1-S2] inline — Add secure workspace `.env` loading, a local Councilbox profile/template, usage documentation, and deterministic tests — commit: `feat(cli): load workspace dotenv for local publication` (done)
- T2 [S1-S2] inline — Verify the local-only workflow against the public CLI interface and assess its credential-handling risk — commit: `feat(cli): load workspace dotenv for local publication` (done)

## Log

- L1: "dejame todo armado en local para solo tener que poner los secrets y demas.... ten en cuenta que por norma general usaremos .env no?"
- L2: "si lo ejecuto en local es decir desde mi pc apuntnando a otro repo no quiero tocar nada del otro repo, no estamos configurando la action"
- L3: Read-only discovery: a direct external-target run without `--config` correctly uses secure defaults and reports both integrations as `NOT_CONFIGURED`. Local Dependency-Track and DefectDojo authentication succeeds with the compose endpoints and existing local token files. DefectDojo has a `CBX` product type; no `councilbox-server` product exists.
- L4: Implemented workspace-local `.env` loading and a Councilbox Server profile. Added non-secret endpoint defaults and blank credential placeholders to this workspace's ignored `.env`; the operator must provide `DTRACK_API_KEY` and `DOJO_TOKEN`.
- L5: Verification: 98-test stdlib suite passed; local profile authenticated both services with read-only `barad health`; a base-versus-change public CLI differential without `.env` was unchanged. Independent security verification passed S1 and S2 with no blockers.

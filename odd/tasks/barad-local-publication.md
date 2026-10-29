# Barad local publication setup

Local CLI-only workflow for publishing external repository scan results without modifying scan targets.
The feature is security-sensitive because it loads runtime integration credentials.

## Specs

S1. "dejame todo armado en local para solo tener que poner los secrets y demas.... ten en cuenta que por norma general usaremos .env no?"

S2. "si lo ejecuto en local es decir desde mi pc apuntnando a otro repo no quiero tocar nada del otro repo, no estamos configurando la action"

S3. "Publicar ramas separadas"

S4. "Añadir detalle seguro"

## Tasks

- T1 [S1-S2] inline — Add secure workspace `.env` loading, a local Councilbox profile/template, usage documentation, and deterministic tests — commit: `feat(cli): load workspace dotenv for local publication` (done)
- T2 [S1-S2] inline — Verify the local-only workflow against the public CLI interface and assess its credential-handling risk — commit: `feat(cli): load workspace dotenv for local publication` (done)
- T3 [S3] inline — Derive a safe branch-specific remote identity for local publication and cover it with contract tests — commit: `feat(integrations): isolate local branch publications` (done)
- T4 [S4] inline — Surface a bounded, secret-safe Dependency-Track validation detail and cover it with tests — commit: `fix(integrations): expose safe dependency-track errors` (done)

## Log

- L1: "dejame todo armado en local para solo tener que poner los secrets y demas.... ten en cuenta que por norma general usaremos .env no?"
- L2: "si lo ejecuto en local es decir desde mi pc apuntnando a otro repo no quiero tocar nada del otro repo, no estamos configurando la action"
- L3: Read-only discovery: a direct external-target run without `--config` correctly uses secure defaults and reports both integrations as `NOT_CONFIGURED`. Local Dependency-Track and DefectDojo authentication succeeds with the compose endpoints and existing local token files. DefectDojo has a `CBX` product type; no `councilbox-server` product exists.
- L4: Implemented workspace-local `.env` loading and a Councilbox Server profile. Added non-secret endpoint defaults and blank credential placeholders to this workspace's ignored `.env`; the operator must provide `DTRACK_API_KEY` and `DOJO_TOKEN`.
- L5: Verification: 98-test stdlib suite passed; local profile authenticated both services with read-only `barad health`; a base-versus-change public CLI differential without `.env` was unchanged. Independent security verification passed S1 and S2 with no blockers.
- L6: User selected "Publicar ramas separadas" when asked which policy Dependency-Track should use for a local temporary branch. This reopens the feature for T3.
- L7: Independent verification blocked T3: a valid non-ASCII branch name could produce no ASCII slug and fall back to the stable remote version. Add regression coverage for that case and for the opt-out skip before closing T3.
- L8: Fixed the Unicode/punctuation branch fallback with a constant slug plus SHA-256 branch digest. Added direct regression coverage for it and the opt-out temporary-branch skip. The 101-test suite and independent re-verification passed S3.
- L9: User selected "Añadir detalle seguro" after Dependency-Track created the remote project/version but rejected the SBOM with HTTP 400. The detail must not include tokens or the SBOM.
- L10: T4 exposes only a whitespace-normalized, 240-character JSON `message`, redacts configured tokens/endpoints, and omits non-JSON responses. The 102-test suite and independent security re-verification passed S4.

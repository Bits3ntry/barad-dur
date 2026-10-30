# BARAD-DÛR platform (POC) — 5-command quickstart

The platform API is the management layer over the scan evidence the `barad` CLI produces: SBOM ingestion with receipts, dependency inventory, OSV-backed vulnerability findings, secrets/misconfigurations/SAST incidents with the two-layer suppression workflow, a CI pipeline/run registry with fail-closed gate verdicts, and static scope. The clean-room clone replaces OpenCTM's platform layer with ours while Dependency-Track/DefectDojo/Trivy/OpenGrep stay as engines.

## Five commands (fresh machine, existing Compose stack)

```sh
# 1. install the platform API (versions the checkout's backend/)
.venv/bin/pip install -e backend

# 2. create the database role/database once (and the matching secret in .env)
docker exec barad-dur-postgres-1 psql -U dtrack -d dtrack \
  -c "CREATE ROLE barad LOGIN PASSWORD '...'"
docker exec barad-dur-postgres-1 psql -U dtrack -d dtrack \
  -c "CREATE DATABASE barad_platform OWNER barad"

# 3. apply migrations and issue the first API key (prints the raw key once)
.venv/bin/barad-platform migrate
.venv/bin/barad-platform key create --org poc

# 4. serve the API (loopback; the compose service does the same shipping)
.venv/bin/barad-platform serve --port 8090         # or: docker compose up -d platform-api

# 5. put the key where the CLI and console read it, then run/scans
export PLATFORM_API_URL=http://127.0.0.1:8090
export PLATFORM_API_KEY=<the raw key from step 3>
cd /tmp && barad run <project-path> -O /tmp/evidence   # publishes SBOM + findings to the platform
cd frontend && npm install && npm run dev              # console at http://127.0.0.1:5173 (proxy to :8090)
```

CLI credentials ride the invocation workspace's `.env` (same file the other integrations use: `PLATFORM_API_URL`, `PLATFORM_API_KEY`); the console stores its copy in localStorage from the settings panel.

## The four delivery surfaces

| Surface | Where | Notes |
|---|---|---|
| Platform API | `backend/` (FastAPI, SQLAlchemy, Alembic; `src/` layout, entrypoint `barad-platform`) | Migration chain `0001_core → 0004_ci_scope`; per-kind fingerprint recipes; suppression workflow with no-self-approval; CI gate verdicts fail-closed at HIGH+. |
| CLI integration | `integrations/platform_api/` + `cli/barad/run.py` | Third integration in `.barad.yml` (`integrations.platform_api.enabled: true`, envs `PLATFORM_API_URL`/`PLATFORM_API_KEY`). CI context (GitHub Actions) registers the run, links findings and closes the run with the verdict. |
| Console | `frontend/` (Vite + React 18 in plain JS) | Four sections: findings (+detail/dispositions), components (+manual SBOM upload, source=web), pipelines/runs (verdict badges + capped reasons), settings. Dev proxy `/api → 8090`. |
| Compose | `platform-api` service | Digest-pinned `python:3.12-slim`, non-root, migrations at boot, loopback publish, health via `/healthz`. |

## What the POC deliberately leaves after (post-POC backlog)

OIDC trust for the CI plane, `ci_gate_policies`/overrides, SLA/priority machinery, ticketing, audit hash chain, scope attestation letters and approvals, multi-tenant surfaces, severity scoring from CVSS vectors, OSV pagination, suppression expiry re-application, centralized CVsS/verdict UI polish. The verification record for every claim lives in `docs/architecture/AUDIT.md`.

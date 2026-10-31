# Barad-dûr operations runbook

Verified against the live deployment (compose project `barad-dur`, loopback
only). Update this file when the deployment contract changes.

## Services and ports

| Service | Port (loopback) | Health |
|---|---|---|
| platform-api | 8090 | `GET /healthz` → `{"status":"ok"}` |
| console (nginx) | 8092 | `GET /` (proxies `/api` to platform-api) |
| postgres | 15443 | `pg_isready` inside container |
| dependency-track | 18080 / 18081 | DT UI |
| defectdojo | 18082 | Dojo UI |

## Deploy / upgrade procedure

```sh
# 1. sync source into the deployment directory (worktree -> deploy root)
rsync -a --delete --exclude __pycache__ backend/ /Volumes/.../Barad-d-r/backend/
# 2. apply migrations against the live DB (head is idempotent)
PLATFORM_DATABASE_URL="postgresql+psycopg://barad:***@127.0.0.1:15443/barad_platform" \
  .venv/bin/barad-platform migrate
# 3. rebuild + restart the API, refresh the console dist
docker compose build platform-api && docker compose up -d platform-api console
# 4. smoke
curl -sf http://127.0.0.1:8090/healthz
curl -s http://127.0.0.1:8090/openapi.json | jq '.paths | length'
```

Console release only: `npm run build` in `frontend/` → rsync `dist/` →
`console_html/` → `docker compose up -d console` (nginx serves the new hash).

## Backups

Nightly logical backup (keeps 7 days). Run from the deployment directory:

```sh
docker exec barad-dur-postgres-1 pg_dump -U dtrack -Fc barad_platform \
  > backups/barad_platform-$(date +%F).dump
find backups -name 'barad_platform-*.dump' -mtime +7 -delete
```

Restore (into a FRESH database, never over a live one):

```sh
docker exec barad-dur-postgres-1 createdb -U dtrack barad_platform_restore
docker exec -i barad-dur-postgres-1 pg_restore -U dtrack -d barad_platform_restore \
  < backups/barad_platform-2026-10-31.dump
```

The `barad-dur_migration-backup` volume holds the pre-cutover dumps and is
external + read-only by contract (never removed by `down -v`).

## Recurring scans

Schedules are queued by a tick the platform never runs by itself. Add a cron
entry on the host (crontab -e):

```cron
* * * * * curl -s -X POST http://127.0.0.1:8090/api/v1/orchestration/schedules/tick \
  -H "X-API-Key: $BARAD_CRON_KEY" -H 'Content-Type: application/json' -d '{"actor":"cron"}' >/dev/null
```

Each due schedule advances its clock before queueing, so an overlapping tick
cannot duplicate a run; a denied schedule records the denial and still waits
for its next interval.

## Shauron worker

```sh
# preferred: a scoped worker token (cannot read findings, grants or audit)
barad worker --platform-url http://127.0.0.1:8090 --worker-token "$WORKER_TOKEN" \
  --name worker-1 --capability vulnerability_analysis --limit 1

# mint one (admin) — raw value returned once
curl -X POST http://127.0.0.1:8090/api/v1/orchestration/workers/$WORKER_ID/tokens \
  -H "X-API-Key: $ADMIN_KEY" -H 'Content-Type: application/json' \
  -d '{"label":"edge-1","expires_hours":720,"actor":"ops"}'
```

Queue jobs from the console (orchestration tab) or the API with a profile
`{"target_path": "/srv/repo", "project": "saria", "version": "1.4.0"}`.
The worker only receives jobs the platform already authorized, re-validates
the grant at claim time, and reports failure with the tool's own error text
when a scan cannot produce evidence. Artifacts: SBOM (CycloneDX) and SAST
(SARIF) are ingested back into the job's project version.

## SLA notifications

Create a webhook channel (admin) and point it at your receiver; the secret is
returned once and used to sign every delivery
(`X-Barad-Signature: sha256=…`). Run the tick from cron next to the scan
scheduler:

```cron
30 * * * * curl -s -X POST http://127.0.0.1:8090/api/v1/notifications/tick \
  -H "X-API-Key: $BARAD_CRON_KEY" -H 'Content-Type: application/json' -d '{"actor":"cron"}' >/dev/null
```

Deliveries are deduped per channel per day; failures are recorded in
`GET /api/v1/notifications/deliveries` with the HTTP code and error.

## SCM publishing

Set `GITHUB_TOKEN` (repo:status + pull_requests:write) and optionally
`GITHUB_API_URL` (defaults to `https://api.github.com`), then
`docker compose up -d platform-api`. The publish action posts a commit
status (`barad-dur/security`, state from the gate verdict) and keeps a
single marker comment per PR, updating it on re-runs. Unset token ⇒ 503
`scm_not_configured`.

## Jira integration (BL-050)

Dormant until configured: set `JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_TOKEN`
(API token) and `JIRA_WEBHOOK_SECRET` in `.env`, then
`docker compose up -d platform-api`. Point the Jira webhook at
`https://<barad-host>/api/v1/jira/webhook` with header `X-Barad-Secret`.
While unconfigured, links are queued in `jira_outbox` (dedupe keys) and the
API reports `jira_configured: false` — it never fakes a sync. A Jira issue
reaching Done flips the link to `verification_required`; findings still need
their own verification.

## Users and roles

`BOOTSTRAP_TOKEN` (in `.env`) enables first-run owner creation; unset it after
onboarding if the API is reachable by anyone else.

```sh
curl -X POST http://127.0.0.1:8090/api/v1/auth/bootstrap \
  -H "X-Bootstrap-Token: $BOOTSTRAP_TOKEN" -H 'Content-Type: application/json' \
  -d '{"org_slug":"poc","email":"you@company.dev","password":"********"}'
```

Roles: `owner` (everything), `admin` (identity, grants, policies, orchestration),
`analyst` (operational writes), `viewer` (read-only). API keys remain the
service identity with full org rights. Sessions last `SESSION_TTL_HOURS`
(default 12) and are revoked on logout, password reset or user disable.

OIDC is available when `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`,
`OIDC_REDIRECT_URI` are set **and** the optional `cryptography` extra is
installed; otherwise `/auth/oidc/*` answers 503 with the reason.

## Secrets

All secrets live in the deployment `.env` (gitignored, chmod 600):
`barad_db_password`, `DT_DB_PASSWORD`, `DD_*`, `TRIVY_SERVER_TOKEN`.
Never print them; regenerate with `openssl rand -hex 24`.

## Health & troubleshooting

- `docker ps` then `docker logs barad-dur-platform-api-1 --since 5m`.
- 8090 occupied by a stray host process: `lsof -nP -iTCP:8090 -sTCP:LISTEN`,
  kill the offender, `docker compose up -d platform-api`.
- Migration drift symptoms (`column ... does not exist`): compare models vs
  migrations; ship an additive fix-up migration, never rewrite an applied one.
- Audit chain broken: `GET /api/v1/audit` returns `chain_ok:false` — the
  ledger or a row was tampered; restore from the last good backup and
  investigate before continuing.

## Test/rehearsal fixtures

- Gate creds: `/tmp/barad-gate/client.env` (chmod 600, outside the repo).
- Live key issuance: `.venv/bin/barad-platform key create --org poc`.

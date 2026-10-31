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

# DefectDojo CE and scanners — single-stack operation

All services live in the root `compose.yaml` (project `barad-dur`). There is intentionally **no second Compose file**: two projects meant two sets of networks, secrets and commands, and a `docker compose` call in a subdirectory silently ignored the root `.env`.

## DefectDojo CE

7 services (nginx, uwsgi, celery worker, celery beat, initializer, Postgres 18.6, Valkey 9.1.2), images 3.4.202. Reference: [upstream Compose](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/3.4.202/docker-compose.yml) and [DOCKER.md](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/3.4.202/readme-docs/DOCKER.md). This adaptation drops the build context, the published TLS port and upstream's default passwords. ARM64 images carry manifest entries but upstream integration tests do not cover ARM64.

Postgres and Valkey sit on `dojo-internal` (`internal: true`, no route off-host). Only `dojo-nginx` publishes, and only on `127.0.0.1:18082`.

```sh
docker compose config --quiet
docker compose up -d
docker compose ps
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18082/   # 302 -> /login
```

`dojo-initializer` runs once and exits 0. It appears as `Exited (0)` and that is correct — `docker compose ls` counts it as "not running", not as a failure. It only sets the admin password when the database is new; on an existing database it does nothing, so **the first-run password is not reproduced**. If it is lost, reset it deliberately:

```sh
docker exec -i barad-dur-dojo-uwsgi-1 ./manage.py shell -c "
import sys
from django.contrib.auth.models import User
u = User.objects.get(username='admin'); u.set_password(sys.stdin.readline().strip()); u.save()"
```

Pipe the new password on stdin so it never appears in shell history or process arguments. Local credentials for this POC are in `.secrets/defectdojo-admin.txt` (mode 600, gitignored).

Create findings only from real reports: `Import Scan` in the CE UI with a supported parser, or the API. Never mark a finding closed without a supervised retest. The requested `Detected → Triaged → Assigned → In Remediation → Pending Retest → Verified/Closed` flow is a **mapping proposal**; DefectDojo's actual status flags and deduplication semantics must be confirmed against the running version.

Deduplication is currently **disabled** (`enable_deduplication=False`, `delete_duplicates=False`, `false_positive_history=False`). Enabling it is a deliberate decision: it changes how re-imports merge findings, and `delete_duplicates=True` removes records. Verify on a copy first.

Before any non-local use: TLS, SSO, product/team authorization, audit logging, secrets vault, pinned digests, egress policy and a rehearsed restore.

## Scanners in the same stack

No web UI exists for any of them. They are `profiles: [tools]` services, so `docker compose up -d` does **not** start them and they cost nothing while idle.

```sh
docker compose --profile tools run --rm trivy --version
docker compose --profile tools run --rm syft version
docker compose --profile tools run --rm cyclonedx --version
```

Mounts: `${SCAN_ROOT:-.}` read-only at `/scan`, `./artifacts` read-write at `/output`, Trivy's cache in the shared `barad-dur-trivy-cache` volume.

```sh
# SBOM from source + standards validation
docker compose --profile tools run --rm syft dir:/scan -o cyclonedx-json=/output/sbom.cdx.json
docker compose --profile tools run --rm cyclonedx validate \
  --input-file /output/sbom.cdx.json --input-format json --input-version v1_7 --fail-on-errors

# Repository scan via the wrapper (adds JSON + SARIF + CycloneDX outputs)
sh scripts/scanners/trivy.sh fs . artifacts/trivy/repository
```

`cyclonedx` runs with `network_mode: none`: it validates locally and cannot exfiltrate anything. Trivy and Syft need egress for their advisory database and image pulls, so they attach to `edge`.

Scanning has no CI integration, no schedule and no privilege to reach production. A repository SBOM never proves what is deployed: source, image and deployed-artifact inventories are distinct evidence and must be recorded as such.

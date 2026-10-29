# PostgreSQL unification
Objective: run Dependency-Track and DefectDojo against one local PostgreSQL server while retaining separate databases and roles.
Branch: feat/barad-security-workflow · Delivery strategy: ask-on-risk · Test runner: Docker Compose structural and live migration validation.

## Specs
1. S1 — "el postgres esta unificado?"
2. S2 — "podemos unificar no?"
3. S3 — "si"
4. S4 — "Preservar y migrar"
5. S5 — "esto se puede eliminar no? al final usaremos trivi para todo....... despuyes levanta el nuevo setup con la infra establecida 1 unico postgres etc..."

## Tasks
- T1 · S1-S4 · delegated · done · Consolidated PostgreSQL services; verified restored relation counts, healthy UIs, and stopped legacy database containers; commit: pending.
- T2 · S5 · inline · done · Removed the Syft and CycloneDX on-demand Compose services; retained Trivy server and CLI; commit: pending.

## Log
- L1 · User request: "si"
- L2 · Scope established from the preceding questions: consolidate the two local PostgreSQL containers without merging application databases.
- L3 · No meaningful RED test exists for this declarative Compose-only change. Docker/OrbStack is unavailable; validate structurally with `docker compose config --quiet` and inspect the rendered dependency graph.
- L4 · The context backstop requires the bounded implementation unit to be delegated; its allowed edit surface is `compose.yaml` only.
- L5 · `dt-db` and `dojo-db` are explicitly adopted pre-existing volumes. Unifying PostgreSQL without a migration or explicit reset could discard their contents; implementation is blocked pending a data-retention decision.
- L6 · User decision: "Preservar y migrar".
- L7 · Docker/OrbStack is not running. A data-preserving consolidation requires live `pg_dump` backups, restore verification, and a rollback point; task waits for the daemon.
- L8 · Docker is running. The retained source databases are 3117 MB (`dtrack`) and 30 MB (`defectdojo`); migrate them through a backup volume before switching application containers.
- L9 · User scope expansion:
  ```text
  syft:
      image: anchore/syft:v1.55.0
      profiles: [tools]
      volumes:
        - "${SCAN_ROOT:-.}:/scan:ro"
        - "./artifacts:/output"
      networks: [edge]
      working_dir: /scan

    # Pure local validator: no network at all.
    cyclonedx:
      image: cyclonedx/cyclonedx-cli:0.33.1
      profiles: [tools]
      volumes:
        - "./artifacts:/output"
        - "./catalog/schema:/schema:ro"
      network_mode: none esto se puede eliminar no? al final usaremos trivi para todo....... despuyes levanta el nuevo setup con la infra establecida 1 unico postgres etc...
  ```
- L10 · Live migration reproduced a DefectDojo startup blocker: the ownership-reassignment query attempted to alter a sequence linked to a table, so the init script exited before writing the readiness marker. The source volumes and verified dumps remain intact.
- L11 · The corrected initializer runs only on an empty data directory. Completing the target therefore requires deleting and recreating `barad-dur_postgres-db`; it contains only the failed partial restore, while `dt-db`, `dojo-db`, and the verified external backup volume remain intact.
- L12 · User authorized: "Recrear el volumen nuevo".
- L13 · The rebuilt stack is healthy: `dtrack` restored 150 relations, `defectdojo` restored 408; Dependency-Track returned HTTP 200, DefectDojo HTTP 302, and the legacy database containers are stopped while their volumes and migration backup remain intact.
- L14 · Independent live verification passed S1-S5: one healthy project PostgreSQL container; distinct roles/databases with live application sessions; preserved source/backup volumes; healthy Trivy Server; and no Syft/CycloneDX in the tools profile.

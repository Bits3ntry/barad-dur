# Barad-dûr Architecture Consolidation v0.1
Branch: feat/barad-security-workflow. Preserve all pre-existing Git changes; no push, PR, merge, or destructive data operation.
Scope: root Compose; three-command CLI; reusable Dependency-Track and DefectDojo adapters; local GitHub Action adapter.

## Specs
S1: "Reorganiza el repositorio existente de Barad-dûr, sin reconstruir el proyecto desde cero."
S2: "Establecer una arquitectura modular y mantenible centrada exclusivamente en:"; "1. **Docker Compose:** infraestructura general del proyecto, situada en la raíz."; "2. **CLI:** motor de análisis Trivy, ejecutable localmente y mediante GitHub Actions."; "3. **Integrations:** adaptadores reutilizables de Dependency-Track y DefectDojo."
S3: "No desarrollar todavía dashboard, API propia, MCP ni workers de IA."; "- `compose.yaml` en la raíz."; "- `cli/` para los comandos `barad scan`, `barad run` y `barad health`."; "- `integrations/dependency_track/` para gestionar proyectos, versiones y SBOM."; "- `integrations/defectdojo/` para importar y reimportar hallazgos."; "- `action/` como adaptador de GitHub Actions."; "- `tests/` para validar CLI e integraciones."; "- `docs/` para documentación vigente."
S4: "Audita todas las implementaciones existentes antes de modificar archivos."; "Consolida la lógica duplicada entre `barad_security/` y `cli/barad/`."; "Mantén una única implementación de Trivy, SBOM, inventario, versión y evidencia."; "Extrae los adaptadores de DT y DJ a `integrations/` sin romper los imports ni la instalación del paquete."
S5: "Conserva el PostgreSQL unificado, las bases existentes y los servicios Docker operativos."; "No introduzcas Syft ni CycloneDX CLI."; "No crees carpetas vacías para servicios futuros."; "Conserva `odd/tasks/` si es necesario para el agente."; "Respeta todos los cambios preexistentes del árbol Git."; "No elimines volúmenes, backups, datos persistentes ni configuraciones funcionales."
S6: "Mantén exactamente tres comandos:"; "- `barad scan`: genera `security.json`, `sbom.cdx.json` y `manifest.json` localmente."; "- `barad run`: ejecuta el análisis y sincroniza los resultados con Dependency-Track y DefectDojo según cambios y configuración."; "- `barad health`: verifica las herramientas, configuración y conexiones sin modificar datos."; "Los mismos comandos deben funcionar en terminal local y GitHub Actions."
S7: "Validar Docker Compose."; "Verificar que DT, DJ y Trivy Server siguen operativos."; "Instalar el CLI desde una ubicación externa al repositorio."; "Ejecutar `barad scan` contra un proyecto de prueba."; "Ejecutar `barad run` contra proyectos de prueba aislados."; "Verificar publicación de SBOM e importación/reimportación de hallazgos."; "Ejecutar los tests existentes y corregir los afectados por la reorganización."; "Actualizar documentación y referencias a rutas anteriores."; "No declarar funcionalidad como validada si no se ha comprobado realmente."

## Tasks
T1 [S1-S5] parent audit and architecture baseline; done; evidence: current/HEAD implementation map and pre-existing worktree audit recorded in Log L2.
T2 [S2-S6] inline; reusable DT/DJ adapters moved to `integrations/` with compatibility imports and package installation; adapter commit bb2bfef, independent verification PASS. The concrete GitHub Action adapter is in the closing core/docs slice.
T3 [S2-S6] inline; CLI-owned scanning/evidence boundaries consolidated, valid empty Trivy reports fixed, and CLI/integration tests rooted at `tests/`; commit 29c72fa.
T4 [S3,S7] inline; workflow/docs/former paths reconciled, installed CLI and Docker configuration validated; commit 29c72fa.
T5 [S5,S7] inline; isolated health, scan, DT SBOM publication, and DefectDojo import/reimport PASS; commit 29c72fa.
T6 [S1-S7] parent; complete checks and independent reviews PASS; native assessment was unassessable only because a pre-existing untracked task file remains. User selected preservation of all pre-existing legacy deletions without committing them; closure commit pending.

## Log
L1: # BARAD-DÛR — Architecture Consolidation v0.1

Reorganiza el repositorio existente de Barad-dûr, sin reconstruir el proyecto desde cero.

## Objetivo

Establecer una arquitectura modular y mantenible centrada exclusivamente en:

1. **Docker Compose:** infraestructura general del proyecto, situada en la raíz.
2. **CLI:** motor de análisis Trivy, ejecutable localmente y mediante GitHub Actions.
3. **Integrations:** adaptadores reutilizables de Dependency-Track y DefectDojo.

No desarrollar todavía dashboard, API propia, MCP ni workers de IA.

## Arquitectura

- `compose.yaml` en la raíz.
- `cli/` para los comandos `barad scan`, `barad run` y `barad health`.
- `integrations/dependency_track/` para gestionar proyectos, versiones y SBOM.
- `integrations/defectdojo/` para importar y reimportar hallazgos.
- `action/` como adaptador de GitHub Actions.
- `tests/` para validar CLI e integraciones.
- `docs/` para documentación vigente.

## Reglas de refactorización

1. Audita todas las implementaciones existentes antes de modificar archivos.
2. Consolida la lógica duplicada entre `barad_security/` y `cli/barad/`.
3. Mantén una única implementación de Trivy, SBOM, inventario, versión y evidencia.
4. Extrae los adaptadores de DT y DJ a `integrations/` sin romper los imports ni la instalación del paquete.
5. Conserva el PostgreSQL unificado, las bases existentes y los servicios Docker operativos.
6. No introduzcas Syft ni CycloneDX CLI.
7. No crees carpetas vacías para servicios futuros.
8. Conserva `odd/tasks/` si es necesario para el agente.
9. Respeta todos los cambios preexistentes del árbol Git.
10. No elimines volúmenes, backups, datos persistentes ni configuraciones funcionales.

## CLI

Mantén exactamente tres comandos:

- `barad scan`: genera `security.json`, `sbom.cdx.json` y `manifest.json` localmente.
- `barad run`: ejecuta el análisis y sincroniza los resultados con Dependency-Track y DefectDojo según cambios y configuración.
- `barad health`: verifica las herramientas, configuración y conexiones sin modificar datos.

Los mismos comandos deben funcionar en terminal local y GitHub Actions.

## Validación obligatoria

- Validar Docker Compose.
- Verificar que DT, DJ y Trivy Server siguen operativos.
- Instalar el CLI desde una ubicación externa al repositorio.
- Ejecutar `barad scan` contra un proyecto de prueba.
- Ejecutar `barad run` contra proyectos de prueba aislados.
- Verificar publicación de SBOM e importación/reimportación de hallazgos.
- Ejecutar los tests existentes y corregir los afectados por la reorganización.
- Actualizar documentación y referencias a rutas anteriores.

No declarar funcionalidad como validada si no se ha comprobado realmente.

## Resultado esperado

Un repositorio ordenado, sin motores ni adaptadores duplicados, con Docker Compose en la raíz y tres módulos claramente definidos: CLI, integraciones y Action.

Mantener las funcionalidades existentes y preparar una base sólida para ampliar Barad-dûr en el futuro, sin implementar todavía esas ampliaciones.

L2: Audit before modification: the parent recorded the exact HEAD/worktree deletion inventory and current package/Compose state; a read-only explorer mapped the live implementation. The worktree already contains 66 tracked deletions plus pre-existing `odd/tasks/barad-legacy-cleanup.md`; no existing deletion or untracked protected Compose, secret, cache, data, or virtualenv path will be reverted, deleted, or committed incidentally. Current CLI has exactly scan/run/health and one scanning path (`barad_security.trivy`, `barad_security.sbom`, `barad_security.versioning`, `barad_security.evidence` helpers; `cli/barad/{scan,inventory,store,run}`). DT/DJ adapters currently live at `cli/barad/integrations/`; package compatibility is a primary constraint. Compose already owns one PostgreSQL service and protected external backup/rollback volumes. Existing test suite is `cli/tests` (85 tests reported by prior worktree evidence); hosted Actions execution has no local proof.
L3: The completed adapter slice is bb2bfef (`feat(integrations): extract reusable remote adapters`). Independent verification passed all relevant S2-S6 checks: wheel build/installed layout include the new packages; old `barad.integrations.*` paths resolve to the exact same adapter modules and remain mock-patch compatible; moved DT/DJ and inventory functions are AST-identical; no data/config/volume change was in the commit.
L4: Actual operational proof on 2026-10-29: `docker compose config --quiet` passed; PostgreSQL, Dependency-Track API/frontend, DefectDojo nginx/Valkey, and Trivy Server were up/healthy. A wheel installed into a fresh virtual environment outside the repository reported `barad health` HEALTHY for Trivy 0.76.1, DT, and DJ. An isolated project with `requests==2.32.3` completed `barad scan`, writing `security.json`, `sbom.cdx.json`, and `manifest.json` with 2 SBOM components. First `barad run` published DT project `barad-architecture-isolated` version `0.1.0` UUID `516b0f6e-b816-4545-a873-88b836bd835e` and imported DefectDojo test 9 (2 findings, close_old_findings=false); the second run verified DT `UNCHANGED: remote_inventory_verified` and DefectDojo `reimport` to test 9. The first minimal-project scan reproduced Trivy's valid no-Results output and was corrected with a RED/GREEN test. GitHub-hosted execution remains unverified.
L5: User selected verbatim: "Preservarlas sin commit". The pre-existing tracked legacy deletions and `odd/tasks/barad-legacy-cleanup.md` remain intentionally unstaged and uncommitted. Therefore the branch commits bb2bfef and 29c72fa require the current worktree's legacy-deletion set to reproduce the 91-test layout; no pre-existing change was reverted, staged, or committed by this consolidation.

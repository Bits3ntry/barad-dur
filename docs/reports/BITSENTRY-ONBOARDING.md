# Bitsentry en Barad-dûr — qué se hizo y con qué datos

Fecha: 2026-11-01 · Org: `bitsentry` · Dominio: `*.bitsentry.xyz`

Este informe documenta (a) el rediseño de la experiencia, (b) los datos reales
cargados y (c) los defectos que hubo que corregir para que ambos fueran
posibles. Todo lo afirmado acá se verificó contra la instancia que corre en
`127.0.0.1:8090` (API) y `localhost:5173` (consola), no contra documentación.

---

## 1. Rediseño de la experiencia

### Lo que estaba roto (no era solo estética)

| Defecto | Efecto real | Estado |
|---|---|---|
| `useEffect` a nivel de módulo en `ui.jsx` | La consola completa no montaba: `Cannot read properties of null (reading 'useEffect')` | Corregido: registro de tema/densidad en init, sin hook |
| `largeArc` fuera de alcance en el donut | El dashboard entero caía con `ReferenceError` al dibujar el gráfico | Corregido: el valor viaja dentro del arco |
| `--sidebar` sin definir | `grid-template-columns: var(--sidebar) 1fr` era inválido → sidebar apilada sobre el contenido | Corregido: `--sidebar: 254px` |
| `--shadow`, `--focus`, `--overlay`, `--dialog-bg` sin definir | Modales transparentes, sin foco visible, sin sombra | Definidos por tema |
| `#fff` y `rgba(8,9,13,...)` hardcodeados | Texto invisible o topbar negro en tema claro | Reemplazados por tokens |
| Components fijo a `projects[0]`, sin selector ni búsqueda | 1.125 filas de purl que no se podían acotar, y ningún vínculo con findings | Reescrito: selector proyecto/versión, búsqueda, filtro "solo con findings", columna de findings por componente |
| Sin vista por proyecto ni por versión | No se podía responder "¿de qué proyecto es esto y qué tiene?" | Pantalla Projects agrupada por proyecto, con detalle por versión (componentes, licencias, severidades, componentes más expuestos, findings) |
| `Project posture` y Components duplicaban información sin correlacionarla | Dos tablas de proyecto, ninguna con inventario | Una sola tabla "Portfolio by project": versiones, componentes, findings, severidad y KEV |
| Assets pedía pegar el JSON del snapshot | Ni IP ni certificado visibles | Columnas de direcciones y certificado (emisor, días restantes, TLS), collect por fila y sweep de crt.sh |
| Tema oscuro por defecto con texto `#b3b8c6` | “Me cuesta leer”: contraste bajo en sesiones largas | Claro por defecto; oscuro mejorado y a un clic |

### Tokens y legibilidad (medidos en el navegador)

- Fondo `#f7f9fc`, texto `#0f1720` → **contraste 17.11:1** (AAA).
- Texto secundario `#38424f` (antes `#57606a` sobre fondo más oscuro).
- Base tipográfica **15.5px / 1.55** (antes 15px/1.5), tablas 14px, cabeceras de tabla 11.5px.
- Tema oscuro: fondo `#11141b`, texto `#f3f5f9` (antes `#08090d` / `#eceef4`).
- Shell verificado en dos columnas: `254px 1011px`.

### Claridad de configuración: nueva guía de setup

Pantalla **Setup guide** (primera del menú) con seis pasos ordenados, cada uno
explicando *por qué* existe y *qué desbloquea*, con estado leído en vivo:

1. Autorizar alcance (grants) — nada se escanea sin grant.
2. Crear proyecto e ingerir SBOM.
3. Decidir qué falla un build (quality gates).
4. Triar los primeros findings.
5. Conectar CI (pipelines).
6. Incorporar al equipo (members).

Muestra progreso (`n de 6`), porcentaje, y marca el paso actual. El dashboard
enlaza a la guía cuando la organización está vacía.

---

## 2. Datos reales cargados

### Organización y superficie

| Elemento | Valor |
|---|---|
| Organización | `bitsentry` |
| Assets | `bitsentry.xyz`, `*.bitsentry.xyz` (tipo `domain`) |
| Grant | `bitsentry-ci` → `passive_discovery`, `vulnerability_analysis` sobre `*.bitsentry.xyz`, 720 h |
| Gate | `Bitsentry release gate` — falla en HIGH+, bloquea KEV y licencias denegadas |
| Cuentas | `owner@bitsentry.xyz` (owner), `analyst@`, `viewer@` |

Las contraseñas se generaron aleatorias y viven en el `.env` del repo
(`BITSENTRY_OWNER_PASSWORD`, `ANALYST_PASSWORD`, `VIEWER_PASSWORD`), nunca en git.

### Proyectos, repos y artefactos

SBOMs CycloneDX generados con **syft** sobre los repos reales; ingestión por
`POST /api/v1/sbom`; findings por `POST /api/v1/analyze` contra OSV.

| Proyecto | Repo | Versión | Componentes | Findings |
|---|---|---|---|---|
| aurea-frontend | Aurea/aurea-frontend | `2069004` | 881 | 527 |
| aurea-backend | Aurea/aurea-backend | `1923bba` | 1125 | 169 |
| aurea-fx-service | Aurea/aurea-fx-service | `ba335e4` | 400 | 79 |
| aurea-document-service | Aurea/aurea-document-service | `3964ceb` | 126 | 63 |
| saria-backend | saria/backend | `1afcd83` | 362 | 182 |
| saria-ios | saria/ios | `1afcd83` | 0 | 0 |
| bitsentry-xyz | bitsentry.xyz | `b7799dd` | 300 | 247 |

Totales: **3.194 componentes** (nivel organización), **3.377 vínculos**
versión↔componente, **1.267 findings**.

Postura actual: 27 CRITICAL, 253 HIGH, 49 LOW, 938 UNKNOWN; **11 explotados
conocidos (KEV)**; 1.267 nuevos en los últimos 7 días.

`saria-ios` aparece con 0 componentes porque no hay `Package.resolved` en el
árbol y syft no cataloga Swift PM: se prefirió un proyecto vacío y honesto antes
que inventar dependencias.

---

## 3. Defectos de plataforma corregidos en el camino

1. **Migración 0030 con revisión inexistente** (`0029_sast_baselines`):
   `alembic upgrade head` fallaba con `KeyError`. Ahora cuelga de
   `0029_notifications`; se eliminó además un `UNIQUE(org_id, status)` que
   habría permitido un solo `completed` por organización.
2. **Router Trivy sin dependencia de sesión** y con `/freshness` shadowed por
   `/{id}`; ahora responde 200 y el POST devuelve **503 explícito** cuando el
   binario `trivy` no está instalado.
3. **El CLI no leía `.env`**: `barad-platform key create` caía al default
   `barad:barad` y moría con “password authentication failed”. Ahora el
   entrypoint carga el `.env` del workspace sin pisar variables exportadas; la
   librería sigue sin leer archivos (un test lo garantiza).
4. **Ingest de SBOM rompía con componentes repetidos** (syft lista el mismo
   paquete por manifiesto): `uq(version, component)` fallaba. Se deduplica en
   memoria, se respeta `autoflush=False`, y un componente visto como directo y
   transitivo queda directo. Un SBOM sin `components` ahora es válido.
5. **Consola rota por dos bugs de React/SVG** (ver §1).

Cada uno tiene test de regresión: 186 pruebas de backend en verde
(`backend/tests`, incluye `test_trivy_db_endpoints.py`, `test_db_dotenv.py`,
`test_sbom_ingest_shapes.py`).

---

## 4. Cómo entrar

```sh
# API (contenedor)
open http://127.0.0.1:8090/healthz

# Consola servida por el contenedor (bundle nuevo, proxy /api al platform)
open http://127.0.0.1:8092

# Consola en modo desarrollo (HMR)
cd frontend && npm run dev     # http://localhost:5173
```

El contenedor `console` ahora monta `console_html/` de **este** checkout
(gitignored, generado con `npm run build`), así que 8092 sirve la UI nueva.
Verificado: asset `index-C8UjD9qc.js`, tema claro, shell `254px 1011px`,
7 proyectos en alcance y 1.267 findings.

Dos formas de identificarse:

- **API key** (máquina): la de `bitsentry` está en `.env` como `BITSENTRY_API_KEY`;
  se pega en Settings y resuelve con rol owner.
- **Login humano**: `owner@bitsentry.xyz` con la contraseña de `.env`
  (`BITSENTRY_OWNER_PASSWORD`). `analyst@` y `viewer@` existen para mostrar RBAC.

El contenedor `barad-dur-console-1` monta `console_html/` de este checkout; si
se ve una UI vieja en `:8092`, el bundle no se copió después del build.

---

## 5. Qué datos existen hoy, por fuente

| Fuente | Qué aporta | Volumen real |
|---|---|---|
| syft (SBOM CycloneDX) | inventario de componentes por proyecto y versión | 3.378 componentes en 7 versiones |
| OSV | vulnerabilidades sobre esos componentes (CVE, KEV, CVSS) | 1.267 findings: 27 CRITICAL, 253 HIGH, 231 MEDIUM, 51 LOW, 711 sin vector |
| opengrep 1.33.1 (`--config auto`) | SAST: debilidades de código con archivo y línea | 67 findings `code-weakness` en los 7 proyectos |
| DNS + TLS (EASM) | direcciones reales y certificado con vencimiento | `bitsentry.xyz` → 188.114.97.5 / .96.5, cert Google Trust Services, vence 20-dic-2026 (49 días), TLSv1.3 |

SAST se ejecuta con `scripts/sast_bitsentry.py`: escanea cada repositorio con
opengrep, guarda el SARIF en `~/.hermes/cache/scratch/sast/` y lo ingiere vía
`POST /api/v1/sarif?project=&version=` (idempotente). Los resultados por
proyecto: aurea-backend 27, aurea-fx-service 15, aurea-frontend 8,
bitsentry-xyz 5, saria-backend 3, aurea-document-service 1, saria-ios 1.

Nota sobre el conteo: un *finding* de código es una debilidad por regla+archivo
y cada línea donde aparece es una *occurrence*. Por eso 55 resultados de
opengrep en aurea-backend son 27 findings: las repeticiones están registradas
como sightings, no descartadas.

## 6. Límites conocidos

- **Pipelines = 0**: no hay CI conectada todavía; la guía lo marca como paso
  pendiente (5 de 6 hechos).
- **711 findings en UNKNOWN**: OSV devolvió avisos sin vector CVSS mapeable.
  Es honesto mostrarlos sin severidad antes que asignarla por suposición.
- **iOS sin inventario**: falta `Package.resolved` o un catálogo Swift en syft.
- **Frescura del DB de Trivy**: solo por API (`/easm/trivy-db/updates/freshness`),
  sin pantalla; el POST responde 503 en este despliegue.
- **EASM activo**: DNS y TLS funcionan on-demand (`collect` desde la tabla o por
  API) con grants por principal; no hay recolección programada ni puertos/HTTP.
- **SAST no corre en CI**: opengrep se ejecuta a mano con el script; conectar los
  pipelines es el paso 6 de la guía que sigue pendiente.
- **Ruido de inventario**: syft también cataloga archivos, así que en
  Components aparecen filas sin PURL cuyo "nombre" es una ruta
  (`…/METADATA`). Son reales pero no son paquetes; el arreglo limpio es
  filtrarlas en el catálogo (nombre que empieza con `/` y sin PURL) o plegarlas
  detrás de un toggle en la pantalla. No se hizo para no borrar filas ya
  ingeridas sin una decisión tuya.

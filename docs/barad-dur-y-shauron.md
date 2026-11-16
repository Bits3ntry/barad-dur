# Barad-dûr y Shauron

**Qué son, cómo se reparten el trabajo y qué garantiza el diseño.**

Barad-dûr **decide**. Shauron **ejecuta**. Todo lo demás en este documento es la consecuencia de esa frase.

Son dos repositorios separados (`Barad-d-r/` y `../shauron`) que se comunican por un contrato versionado y firmado. No comparten base de datos, ni código de dominio, ni credenciales: comparten un sobre (`barad-ticket-v1`) y una forma de devolver evidencia (`barad-evidence-v1`).

---

## La división, en una tabla

| | Barad-dûr | Shauron |
|---|---|---|
| **Qué es** | Plataforma CTEM: API FastAPI, consola React, Postgres | Plano de ejecución: CLI, daemon, GitHub Action, worker, agente |
| **Qué guarda** | Inventario, hallazgos, grants, historial, decisiones | Nada permanente: un directorio de corrida y el disco |
| **Qué decide** | Qué se puede escanear, con qué capacidad, quién lo aprueba, qué se prioriza | Qué herramienta corre cada paso, con qué versión, cómo se normaliza |
| **Qué produce** | El veredicto y el registro | El artefacto y la observación tipada |
| **Depende de** | Postgres | El ticket y los binarios pinneados |

La regla que sostiene todo: **una herramienta nunca sabe que existe la plataforma**. Escribe un archivo dentro del directorio de corrida; el runner —el mismo código en una laptop, en un worker o en un swarm— lo normaliza y lo sube. Una herramienta que habla HTTP con Barad-dûr sería la segunda implementación que siempre se desvía.

---

## Barad-dûr

Es una plataforma local de evaluación, no un SaaS. Levanta con Docker Compose: API en `:8090`, consola en `:8092`, Postgres en `:15443`. El objetivo es responder cuatro preguntas con evidencia: **qué tenemos, qué le falta, qué importa, y quién lo decidió.**

### Qué guarda

Dos cadenas, no dos tablas sueltas:

- **Inventario de software:** proyecto → componente → versión → build. Un build llega como SBOM (CycloneDX) y de ahí salen componentes, dependencias, licencias y CVEs. Un mismo SBOM no se reprocesa dos veces: la idempotencia es `(proyecto, versión, hash del contenido)`.
- **Inventario de superficie:** asset → observación tipada → hallazgo. DNS, TLS, headers, tecnología, puerto, servicio, contenido. Cada observación dice **quién la produjo y con qué cobertura**; cada artefacto, qué motor y qué versión lo generó.

Esas dos cadenas se encuentran en el mismo lugar: un paquete con CVE en un build y un servicio expuesto en un host son dos formas del mismo problema, y la consola las muestra con la misma disciplina.

### Qué decide

- **Autorización.** Un dominio se declara, pero la declaración no elige qué se puede hacer con él. Se pide un *grant*; un administrador aprueba alcance y nivel; el grant es lo que habilita. Los niveles son paquetes de capacidad y las capacidades son tres: `validate`, `discover`, `exploit`. Explotar requiere además un grant y una decisión explícita.
- **Alcance.** Un *zone* es el dominio registrable: todos los subdominios comparten un bucket, y los límites de concurrencia (`per_zone`, `per_org`, `per_worker`, `queue_ceiling`) son una política editable, no un número hardcodeado en un router.
- **Prioridad y triage.** Riesgo explicable (severidad, KEV, EPSS), reglas de priorización, impacto de negocio, y un triage que se hace **desde el run**: quién miró, qué concluyó y cuándo queda en la misma línea de tiempo.
- **IA.** La plataforma es dueña de la clave del proveedor, del presupuesto, del plan y del gate de triage. Los perfiles (`Palantír`, `Angmar`, `Morgoth`) son promesas sobre lo que el sistema **no** va a hacer: `Palantír` solo lee el estado; `Angmar` valida un hallazgo documentado; `Morgoth` descubre y explota, con grant y aprobación.

### Qué muestra

La consola no es un visor de tablas: es el ciclo CTEM en un solo lugar.

- **Dashboard, My work, Findings, Vulnerabilities** — lo que un operador lee todos los días.
- **Ciclo CTEM** — Scoping (ciclos, scope), Inventory (proyectos, assets, attack surface, componentes, exposiciones), Priorización (reglas, impacto).
- **Delivery** — Pipelines (runs de CI), Quality gates, Pentests, Regresión.
- **Supply chain** — Builds (SBOM), Licencias, Orquestación (jobs, workers, escaneos internos), Jira, Remediación.
- **Surface** — runs de reconocimiento con su grafo de pasos, sus observaciones y su cobertura.
- **Settings** — organización, cuenta, apariencia, entrega, claves de servicio y administración (miembros, grants, auditoría, runtime).

### Qué pide ejecutar

La plataforma no escanea: **compone**. Una *action* es un pedido con nombre y tareas:

| Action | Tareas | Red | Qué responde |
|---|---|---|---|
| `code` | `sast`, `secrets` | no | ¿Qué hay en este commit? |
| `supply-chain` | `sbom`, `runtime`, `misconfig`, `secrets` | no | ¿Qué dependemos y qué está mal configurado? |
| `secrets-verified` | `secrets` (con TruffleHog) | sí | ¿Esta credencial sigue viva? |
| `web-surface` | subdominios, DNS, TLS | sí | ¿Qué publicamos sin saberlo? |

---

## Shauron

Es el plano de ejecución. Se entrega en cuatro formas desde un mismo núcleo:

- **`shauron` CLI** — `run`, `scan`, `ticket`, `doctor`, `manifest`, `runtime`, `tools`, `plan`, `surface`, `upload`, `worker`, `agent`, `login`, `show`.
- **`shaurond`** — daemon que acepta tickets por HTTP.
- **GitHub Action** (`action.yml` en la raíz) — mintea el ticket **antes** del trabajo lento, instala los motores pinneados y ejecuta.
- **Worker** — reclama runs encolados de superficie, late antes de cada claim y se retira si el latido falla.

### Escaneo de código

Cinco tipos de tarea: `sbom`, `runtime`, `misconfig`, `secrets`, `sast`. Cada una nombra un **contrato**, nunca un binario: `secrets` puede servirse con Trivy y con gitleaks a la vez, y cada hallazgo conserva el motor que lo produjo. Si un proveedor falla mientras otro entrega, la tarea sigue viva pero el fallo queda nombrado en la evidencia y como *drop*. La tarea falla solo si ningún proveedor entrega.

Los motores están **pinneados por versión y sha256 por plataforma**. Si no hay pin para esa plataforma, se rechaza por nombre; si el binario reporta otra versión, también. Un motor que sale 0 sin escribir su artefacto **no es evidencia**: la tarea se cae con esa razón.

Detalle que suele sorprender: `runtime` no usa motor. Lee lo que el árbol *declara* —`engines.node`, `.nvmrc`, `requires-python`, `.python-version`, `go.mod`, `.ruby-version`, `Dockerfile FROM`— y escribe un CycloneDX con `pkg:generic/<runtime>` o `pkg:docker/<imagen>@<tag>`. Una versión declarada como rango se guarda como rango, nunca se convierte en una versión inventada.

### Escaneo de superficie

El catálogo es **dato**, no código, y el loader falla cerrado: una herramienta desconocida en una etapa, una etapa que lee de otra que no existe, o una capacidad por encima del nivel del perfil hacen fallar el catálogo entero al cargar.

Hoy son **20 herramientas** (nmap, naabu, httpx, whatweb, ffuf, nuclei, sqlmap, dalfox, wp-enum, por nombrar algunas) y **6 perfiles**:

| Perfil | Nivel | Qué hace |
|---|---|---|
| `code.sast` | — | OpenGrep sobre el árbol |
| `code.secrets` | — | gitleaks + Trivy |
| `code.supply-chain` | — | SBOM + runtimes |
| `image.supply-chain` | — | Trivy sobre la imagen |
| `recon.simple` | simple | DNS → TLS → headers → tecnología |
| `web.redteam` | redteam | Lo anterior + puertos, servicios, versiones y descubrimiento de rutas |

Dos reglas de diseño que se sostienen con tests:

1. **Ningún perfil web caza vulnerabilidades.** El producto es reconocimiento. `nuclei`, `dalfox` y `sqlmap` están en el catálogo pero cuelgan de ningún perfil web: el día que uno lo haga, el producto cambió de categoría.
2. **Dos niveles, y el básico es subconjunto estricto del profundo.** No hay un tercer perfil porque no agrega una respuesta nueva.

Los pasos pueden llevar un **gate** (`when: {technology: [wordpress]}`): `wp-enum` no corre en hosts que no son WordPress, y el paso se registra como `dropped` con su razón, nunca como fallo.

### Agente de campo

El bucle vive acá porque acá están las herramientas pinneadas, el sandbox y la posición de red; el razonamiento se proxea a la plataforma (`POST /llm/complete`), así revocar la clave mata a todos los agentes de una.

Lo que el agente puede hacer lo dice el **sobre**, no su criterio: targets con rate limit por host, lista de herramientas, carril (`validate | discover | exploit`), presupuesto de pasos y tokens, deadline y `must_return`. La lista de herramientas que ve el modelo se genera del catálogo: lo que no se le dice, no lo puede elegir. Herramienta fuera del sobre, target negado o presupuesto agotado dejan un `refusal` como evento, con la razón — nunca un skip silencioso.

Una tarea = un contenedor. Un `probe.sibling` es **una** request que verifica la diferencia; el fan-out lo hace la misión que encoló veinte. Agentes largos son agujeros de contexto con tokens.

> El aislamiento del contenedor —red interna sin ruta por defecto, proxy de alcance que resuelve nombres y rechaza IPs literales— es criterio de diseño de la imagen y el proxy; el bucle y el contrato ya están implementados. Se dice así porque todavía no está desplegado.

---

## El contrato

```
CI / laptop / consola
        │  POST /api/v1/scans        (Barad-dûr mintea el ticket)
        ▼
  barad-ticket-v1   firmado, con vencimiento y alcance
        │
        ├── shauron run --ticket        (CI o laptop)
        └── POST /tickets → shaurond    (servicio / worker)
        ▼
  barad-event-v1    →  POST /scans/{id}/events
  barad-evidence-v1 →  POST /scans/{id}/evidence
        ▼
  Barad-dûr: fingerprint, guarda, triagea
```

Cuatro decisiones que valen más que el diagrama:

- **La firma es Ed25519, no HMAC.** La clave privada nunca sale de Barad-dûr; Shauron solo tiene la pública. Con un secreto compartido, un Shauron comprometido podría mintear sus propios tickets y la frontera desaparecería.
- **Autorización con dos economías.** `push` es para quien ya tiene el código (CI, laptop): no contacta nada, así que no necesita grant; la autorización es el vínculo repositorio→proyecto. `allow` es para trabajo que sale de la plataforma (clonar, bajar una imagen, tocar un host): ahí mandan los grants, con sus exclusiones.
- **La evidencia tiene dos transportes.** Envelope JSON para lo chico; el artefacto como cuerpo del request con `kind`, `format`, `hash`, `tool` y `evaluated` en la query para lo grande. Un SARIF real de OpenGrep ronda los 1,9 MB de metadatos de reglas y no entra inline.
- **Un esquema desconocido se rechaza.** `409 unsupported_schema` en vez de adivinar.

---

## Qué garantiza el diseño

1. **Autorización firmada y acotada.** El ticket dice capacidad, principal, scope y `not_after`; Shauron verifica offline y **nunca amplía**.
2. **Evidencia atribuible.** `tools[].version` y `tools[].digest` viajan en el ticket: un hallazgo se puede rastrear hasta el binario exacto, no hasta "trivy, probablemente 0.76".
3. **Cobertura honesta.** `full` o `partial`, y el porqué. Un paso salteado da `partial`: `full` es una afirmación sobre el perfil, no sobre los pasos que casualmente corrieron.
4. **Skip no es fail.** Imagen ausente, adaptador faltante, `scan_aborted` de la propia herramienta: `skipped`, con la frase que lo arreglaría. Si todo gap se pinta rojo, el operador aprende a ignorar el rojo.
5. **Desconocido no es limpio.** Un `404` de "no hay finding que coincida" se lee igual que "nunca escaneamos". La respuesta correcta lleva `unknown` y la razón; una tabla vacía es una pregunta, no una respuesta.
6. **Revocación sin cooperación.** El worker mata el proceso hijo; en el contenedor, el proxy corta el flujo. Ninguna de las dos cosas le pide permiso al agente.

---

## Qué no es

- **No es un SaaS.** Es una plataforma local de evaluación; el objetivo es corrección y trazabilidad, no multi-tenant scale.
- **No es un pentest automático.** El perfil web es reconocimiento; lo intrusivo apunta a un target de práctica y requiere grant.
- **No es un producto de IA.** La IA es una capa: lee el estado, valida un hallazgo o propone una misión, siempre dentro de un sobre y con presupuesto.
- **No reemplaza al humano.** El agente propone; la plataforma guarda; una persona decide. El texto del modelo no es evidencia.

---

## Glosario

- **Asset** — un dominio, subdominio, URL o IP bajo observación.
- **Observación** — un hecho tipado sobre un asset (`dns`, `tls`, `http_headers`, `technology`, `service`, `port`) con fuente y cobertura.
- **Finding** — la conclusión accionable: un CVE en un componente, un secreto expuesto, una debilidad de código, una exposición de superficie.
- **Grant** — la autorización de un principal sobre un scope, con capacidad y vencimiento.
- **Capacidad** — `validate`, `discover`, `exploit`. El único gate real.
- **Ticket** — el sobre firmado que pide trabajo (`barad-ticket-v1`).
- **Run** — una ejecución con su directorio, sus pasos, sus observaciones y su cobertura.
- **Sobre (envelope)** — el contrato de una tarea de agente (`barad-mission-v1`), firmado, con targets, herramientas, presupuesto y deadline.
- **Perfil** — un conjunto de etapas y herramientas con un nivel; no un comando.
- **Coverage** — `full` o `partial`, con razón. La diferencia entre "no encontramos" y "no miramos".

---

## Dónde está cada cosa

- `backend/src/backend/app/routers/` — los dominios de la API (assets, findings, sbom, pipeline, orchestration, surface, agent, authorization).
- `backend/src/backend/app/ai/` — perfiles, orquestador, especialistas, presupuestos.
- `frontend/src/` — la consola (una sola `styles.css`, primitivas compartidas en `ui.jsx`).
- `mcp/` — el servidor MCP que expone el catálogo de la plataforma.
- `../shauron/shauron/core/` — tareas, superficie, contenedores, agente.
- `../shauron/shauron/catalog/` — herramientas y perfiles como dato.
- `../shauron/CONTRACT.md` — el contrato, con los esquemas y la firma.
- `docs/planning/ai-harness-and-mcp.md` — el log de decisiones de la capa de IA.

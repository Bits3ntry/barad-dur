Números, direcciones y vocabularios. Nada de esto es un tutorial; es la hoja que tienes abierta.

### Dónde corre cada cosa

| Cosa | Dirección | Notas |
|---|---|---|
| Consola | `http://127.0.0.1:8092` | nginx sirviendo la consola compilada, `/api` proxeado en el mismo origen |
| API | `http://127.0.0.1:8090` | health en `/healthz`, OpenAPI en `/docs` |
| Postgres | `127.0.0.1:15443` | base `barad_platform`, usuario `barad` |
| Servidor MCP | `barad-mcp` | un proceso, no un puerto; el cliente pone el transporte |

Servicios en el stack provisto: `postgres`, `platform-api`, `console`, `shauron-worker` (el pool que ejecuta), `shauron-scaler` (el único proceso que tiene el socket de Docker), y opcionalmente `scheduler` (el perfil de ops que maneja el tick de advisories cuando el reloj in-process está apagado).

Los bindings a `127.0.0.1` son intencionales. Un runner de CI en otra red necesita `PLATFORM_API_BIND` en una interfaz alcanzable (o un reverse proxy); la consola nunca necesita ser pública.

### Entorno que cambia el comportamiento

| Variable | Efecto |
|---|---|
| `barad_db_password` | la contraseña de la base; obligatoria |
| `BOOTSTRAP_TOKEN` | el código de setup que crea al primer owner. Rotalo después del setup |
| `PLATFORM_API_BIND` / `PLATFORM_API_PORT` | dónde escucha la API; `127.0.0.1` es host-only |
| `CONSOLE_PORT` / `POSTGRES_PORT` | puertos publicados |
| `ADVISORIES_AUTORUN` / `ADVISORIES_POLL_SECONDS` | si la API es dueña del reloj de advisories, y cada cuánto comprueba si el job corresponde |
| `PLATFORM_GEOIP_URL` | geolocalización opcional para el mapa de activos; vacío queda local |
| `NVD_API_KEY` | sube el rate limit de NVD para el matching de CVEs en runtime |
| `JIRA_BASE_URL` / `JIRA_EMAIL` / `JIRA_TOKEN` / `JIRA_WEBHOOK_SECRET` | integración con Jira |
| `GITHUB_API_URL` / `GITHUB_TOKEN`, `GITLAB_API_URL` / `GITLAB_TOKEN` | listar y clonar repositorios |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_FROM` / `SMTP_USER` / `SMTP_PASSWORD` / `SMTP_STARTTLS` | correo saliente |
| `SHAURON_BARAD_KEY` | la API key que usa el worker |
| `SHAURON_WORKER_IMAGE` | qué imagen de worker corre |
| `SHAURON_TOOL_RUNTIME` | `local` corre las herramientas como procesos hijos dentro del worker |

### El mapa de pantallas

Cada pantalla de la barra lateral, qué responde y cuándo abrirla.

| Pantalla | Responde | Abrila cuando |
|---|---|---|
| Panel | dónde está el estate hoy | al arrancar el día; abre con un solo veredicto |
| Mi trabajo | qué es mío y qué vence | cuando te sientas a trabajar una cola |
| Hallazgos | qué necesita una decisión | se movió un hallazgo, o llegó algo nuevo |
| Vulnerabilidades | qué advisories existen y qué tan graves son | alguien pregunta "¿este CVE está en nuestro estate?" |
| Chat | hacerle una pregunta al estate | si no, abrirías tres pantallas |
| Ejecuciones IA | qué hizo el modelo y a qué costo | hay que trazar una respuesta de IA, o un presupuesto la cortó |
| Misiones | trabajo de IA acotado y su presupuesto | quieres que el agente de campo haga una cosa |
| Resumen del ciclo | el loop como marco | estás explicando el programa, no arreglando algo |
| Ciclos | evaluaciones acotadas en el tiempo | una campaña necesita inicio, fin y una referencia congelada |
| Alcance | de qué se puede ocupar este workspace | antes de cualquier proyecto, activo o autorización |
| Proyectos | aplicaciones, componentes, versiones, repositorios | estás incorporando una aplicación |
| Activos | qué se observó, de quién es, cuándo | un activo no tiene dueño, o su estado está en duda |
| Superficie de ataque | superficie observada y decisiones de propiedad pendientes | aparecieron hosts nuevos y nadie los reclamó |
| Componentes | el catálogo de componentes entre proyectos | ¿quién usa esta librería? |
| Exposiciones | cosas alcanzables que no deberían estarlo | revisar qué es alcanzable, no qué es vulnerable |
| Reglas de priorización | cómo se calcula la prioridad | el orden de la lista no cierra con tu política |
| Impacto de negocio | trabajo abierto por aplicación | estás planificando capacidad, no triage |
| Pipelines | commits anunciados, su cobertura y veredicto | un build está bloqueado, o un commit no se escaneó |
| Puertas de calidad | qué bloquea un build | una puerta hace demasiado ruido o no bloquea lo suficiente |
| Pentests | trabajo de engagement a nivel campaña | hay un engagement humano en curso |
| Regresión | qué volvió después de un arreglo | algo marcado como resuelto reapareció |
| Builds | un artefacto: paquetes, advisories, hallazgos de código, secretos | se cuestiona un build, o necesitas su comprobante |
| Licencias | qué contienen los builds, por licencia | legales pregunta, o apareció una licencia prohibida |
| Orquestación | qué corre solo, quién lo corre, qué se ejecutó | una ejecución está trabada, o hay que cambiar un schedule |
| Jira | vínculos hallazgo ↔ ticket y su desvío | el tracker y la consola no coinciden |
| Remediación | ciclo de vida del trabajo | estás siguiendo el cierre, no el triage |
| Guía | cómo funciona todo esto | este documento |

Las pantallas sin fila en la barra lateral se alcanzan desde el registro que las necesita — un activo desde su fila (`#asset::<id>`), una ejecución desde Orquestación (`#surface::<uuid>`), el visor de análisis desde un hallazgo, los pull requests desde una puerta de entrega, y la aprobación de terminal desde la URL que imprime `shauron login` (`#activate::<code>`).

### Vocabularios

**Estado del hallazgo**: `open`, `acknowledged`, `in_progress`, `resolved`, `false_positive`, `accepted_risk`.

**Estado de ejecución**: `queued`, `leased`, `running`, `finished`, `failed`. Una fila `running` de más de una hora se reporta `stale`.

**Cobertura**: `full` (una afirmación sobre el perfil) y `partial` (con el motivo). Los estados de paso incluyen `skipped` y `dropped`, y ninguno de los dos es una falla.

**Niveles de escaneo**: escaneo simple → escaneo avanzado → red teaming, cada uno un superconjunto del anterior.

**Capabilities**: `passive_discovery`, `active_verification`, `vulnerability_analysis`, `intrusive_testing`.

**Lanes de IA**: `validate`, `discover`, `exploit`. Exploit requiere el switch de red team **y** una autorización.

**Confianza de versión** (CVEs en runtime): `exact` (un pin), `range` (un rango declarado), `line` (un tag de imagen que nombra una línea mayor).

### Direcciones que vas a pegar

| Dirección | Abre |
|---|---|
| `/projects/{slug}` | un proyecto |
| `/pipeline` | pipelines |
| `/orchestration` | orquestación |
| `#guide::troubleshooting` | un capítulo de esta guía |
| `#findings::<id>` | un hallazgo |
| `#asset::<id>` | un activo |
| `#surface::<full-uuid>` | una ejecución |
| `#components::<project>/<component>/<version>` | un build |
| `#vulnerabilities::kev=1` | la puerta de explotados conocidos |
| `#activate::<code>` | aprobar un login de terminal |
| `#settings::<section>` | una sección de configuración |

### Teclado

`⌘K` / `Ctrl+K` enfoca el buscador, que salta a cualquier pantalla por nombre. `Esc` lo limpia. Todo lo demás es un clic.

### Idiomas

La consola habla inglés y español. **Configuración → Apariencia → Idioma** cambia toda la interfaz —sidebar, pantallas, formularios y alertas— y la elección queda recordada en este navegador; la guía la sigue capítulo por capítulo. El chip `EN`/`ES` del topbar es el mismo interruptor como atajo.

Añadir un idioma es una carpeta, no un cambio de código: copia `frontend/src/i18n/locales/en/` a una carpeta nueva, traduce los valores y el selector lo ofrece en el próximo build. La guía funciona igual bajo `frontend/src/guide/<lang>/`, y un capítulo que todavía no está traducido lo dice en vez de cambiar en silencio. `npm run i18n` informa qué falta.

Lo que nunca se traduce: los datos —nombres de paquetes, ids de CVE, hostnames, shas de commit, conteos, fechas— y los valores que devuelve la API. Se traduce la etiqueta, nunca el payload.

### Para quien mantiene la plataforma

| Ruta | Contiene |
|---|---|
| `backend/src/backend/app/routers/` | un módulo por dominio de la API |
| `backend/src/backend/app/ai/` | perfiles, orquestador, especialistas, presupuestos |
| `backend/src/backend/app/models.py` | el esquema |
| `backend/migrations/versions/` | el historial lineal de migraciones |
| `frontend/src/` | la consola; una sola hoja de estilos, primitivas compartidas en `ui.jsx` |
| `frontend/src/guide/` | esta documentación, como markdown |
| `mcp/` | el servidor MCP |
| `cli/` | el CLI local `barad` |
| `docs/` | arquitectura, operaciones, planificación y los logs de decisiones |

Desplegar un cambio en la consola es un build más una copia a `console_html/`; el servicio nginx sirve ese directorio entero. Desplegar un cambio de backend significa que la imagen lleva el código nuevo **y** que la migración se ejecutó — un health check en verde no prueba ninguna de las dos cosas.

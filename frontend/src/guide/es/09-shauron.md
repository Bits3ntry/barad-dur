Shauron es el plano de ejecución: el programa que es dueño de las herramientas, el sandbox y la posición de red junto a un objetivo. Es un repositorio aparte, y no guarda nada: un directorio de ejecución y el disco.

La división que hace funcionar todo el diseño:

| | Barad-dûr | Shauron |
|---|---|---|
| Es dueño de | la clave, el presupuesto, el plan, la puerta de triaje | las herramientas, el sandbox, la posición de red |
| Decide | qué se puede escanear, con qué capacidad, por quién | qué herramienta corre cada paso, con qué versión |
| Produce | el veredicto y el registro | el artefacto y la observación tipada |
| Depende de | Postgres | un ticket firmado y binarios pinneados |

No necesitas instalarlo para leer esta consola. Sí lo necesitas para producir evidencia.

### Cómo consigue trabajo: el ticket

La plataforma compone un plan y acuña un **ticket** (`barad-ticket-v1`): un sobre firmado que nombra las tareas, los objetivos, la capacidad, el principal y un vencimiento. Shauron verifica la firma offline y **nunca lo amplía**.

```
CI / laptop / console
     │  the platform mints the ticket
     ▼
  barad-ticket-v1   signed, expiring, scoped
     │
     ├── shauron run --ticket        (CI or laptop)
     └── POST /tickets → shaurond    (service or worker)
     ▼
  events    → POST /scans/{id}/events
  evidence  → POST /scans/{id}/evidence
     ▼
  Barad-dûr: fingerprint, store, triage
```

Cuatro decisiones que importan más que el diagrama:

- **La firma es Ed25519, no un secreto compartido.** La clave privada nunca sale de la plataforma; un escáner comprometido no puede acuñar su propia autoridad.
- **Dos economías.** `push` es para trabajo en una máquina que ya tiene el código (CI, una laptop) — no contacta nada en el objetivo, así que no necesita autorización; la autorización es el vínculo repositorio→proyecto. `allow` es para trabajo que sale de la plataforma (clonar, descargar una imagen, tocar un host) — ahí mandan las autorizaciones.
- **La evidencia tiene dos transportes.** Los documentos chicos viajan inline en un sobre; los artefactos grandes viajan como cuerpo del pedido con el hash, la herramienta y la cobertura en el query. Un SARIF real son megabytes de metadatos de reglas y no entra inline.
- **Un esquema desconocido se rechaza** (`409`), nunca se adivina.

### Las cuatro formas, un solo núcleo

| Forma | Uso |
|---|---|
| `shauron` CLI | una persona, una máquina: escaneo, plan, run, upload, login |
| `shaurond` | un servicio que acepta tickets por HTTP |
| CI action | un workflow de repositorio: acuñar, instalar motores pinneados, escanear, subir |
| worker | reclama ejecuciones en cola, late antes de cada claim, se retira si el latido falla |
| field agent | una tarea de IA acotada en un contenedor desechable |

Todos corren el mismo código de normalización. A una herramienta nunca se le dice que la plataforma existe: escribe un archivo en el directorio de ejecución y el runner lo sube. Una herramienta que hablara HTTP con Barad-dûr sería la segunda implementación que siempre se desvía.

### Comandos que vas a escribir de verdad

| Comando | Qué hace |
|---|---|
| `shauron doctor` | revisa el entorno y los motores pinneados |
| `shauron tools` | imprime el catálogo de herramientas y perfiles, offline |
| `shauron plan --profile … --target …` | compone y muestra un plan de ejecución sin ejecutarlo |
| `shauron surface --profile … --target …` | corre un escaneo de superficie y sube a medida que avanza |
| `shauron scan --platform … --api-key …` | corre un escaneo de código/supply-chain contra la plataforma |
| `shauron run --ticket` | ejecuta un ticket que acuñó la plataforma (el camino de CI) |
| `shauron ticket --out` | anuncia una ejecución antes del trabajo lento, y escribe el ticket |
| `shauron runtime --path . --out runtime.cyclonedx.json` | declara los intérpretes e imágenes base que el árbol declara |
| `shauron upload --run <dir>` | sube una ejecución offline: pasos, después observaciones, después fin |
| `shauron worker --once` / `--loops N --interval S` | reclama ejecuciones de superficie en cola |
| `shauron agent run <task-id>` | corre una tarea de misión de IA |
| `shauron login` / `whoami` / `logout` | el device flow para una sesión humana |

### Escaneo de código: cinco tareas

`sbom`, `runtime`, `misconfig`, `secrets`, `sast`. Cada una nombra un **contrato**, nunca un binario: `secrets` puede servirse con dos motores a la vez, y cada hallazgo conserva el motor que lo produjo. Si un proveedor falla mientras otro entrega, la tarea sobrevive y la falla queda nombrada en la evidencia — un motor roto nunca debe esconderse detrás de uno sano.

Los motores están pinneados por versión y SHA-256 por plataforma. Una plataforma sin pin se rechaza **por nombre**; un binario que reporta otra versión también se rechaza; un motor que sale con 0 sin escribir su artefacto **no es evidencia** y la tarea cae con ese motivo.

`runtime` es la tarea que ningún motor puede servir. No busca paquetes; lee lo que el árbol *declara* (`engines.node`, `.nvmrc`, `requires-python`, `go.mod`, `.ruby-version`, `Dockerfile FROM`) y escribe un documento CycloneDX. Un rango declarado queda como rango.

### Escaneo de superficie: el catálogo es dato

Los perfiles y las herramientas son archivos, no código, y el cargador **falla cerrado**: una herramienta desconocida, un stage que lee de un stage que no existe, una herramienta cuya capacidad está por encima del nivel de su perfil — cualquiera de esas hace que el catálogo entero se niegue a cargar, antes de que empiece un escaneo.

Dos reglas sostienen la categoría del producto:

1. **Ningún perfil web caza una vulnerabilidad.** `nuclei`, `dalfox` y `sqlmap` existen como herramientas pero no cuelgan de ningún perfil web. El descubrimiento de contenido es lo más profundo a lo que llega un tier web.
2. **El tier básico es un subconjunto estricto del profundo.** Dos tiers, porque un tercero sería una tercera opción sin respuesta nueva.

Un paso puede llevar una **puerta**: `wp-enum` corre solo en hosts cuya evidencia acumulada dice WordPress, y cuando no, el paso se registra como `dropped` con su motivo — nunca como una falla. Eso es lo que hace admisible una herramienta cara y selectiva en un perfil que también sirve hosts que no puede leer.

### El field agent

El razonamiento va proxeado a la plataforma (`POST /llm/complete`), así que revocar la clave del proveedor mata a todos los agentes de una vez. El loop, las herramientas y el sandbox viven aquí, porque aquí están los binarios, el aislamiento y la posición de red.

Lo que un agente puede hacer lo decide el **envelope** que recibe, no su criterio: objetivos con límites de tasa por host, una allowlist de herramientas, un carril (`validate` | `discover` | `exploit`), un presupuesto de pasos/tokens/tiempo, `must_return` y una fecha límite. La lista de herramientas que ve el modelo se genera desde el catálogo — lo que no se le dice, no lo puede elegir.

Tres rechazos son siempre **eventos con motivo**, nunca saltos silenciosos: una herramienta fuera del envelope, un objetivo que el comprobación de alcance niega, y un presupuesto agotado.

El alcance se impone por la **ausencia de una ruta**, no por un proxy: el contenedor del agente se une a una red interna cuyo único par alcanzable es el proxy de alcance, porque los sockets crudos ignoran `HTTP_PROXY` y DoH, ICMP y las direcciones link-local nunca hablan HTTP. Eso es lo que hace defendible darle una shell a un agente — la red es la frontera, no el binario.

Una tarea por contenedor, y la tarea es tipada. Un agente de vida larga es un pozo de contexto sin fondo; una tarea que termina no puede serlo.

### El device flow (por qué aparece una URL en tu terminal)

`shauron login` imprime un código corto y una URL. Ese código lo aprueba una **persona** en la consola, en una pantalla oculta (`#activate::<code>`), y una API key nunca puede aprobar uno — una credencial de máquina no debe acuñar una sesión humana.

El código dura poco y no es ambiguo, el secreto se guarda hasheado, y la sesión aterriza en el keychain del sistema operativo. Si alguien pega un token de sesión en un chat, trátalo como filtrado y revócalo.

### Qué garantiza la evidencia

1. **Atribuible**: la versión y el digest de la herramienta viajan con el ticket, así que un hallazgo se rastrea hasta un binario exacto.
2. **Cobertura honesta**: `full` o `partial`, siempre con el motivo. `full` es una declaración sobre el perfil, no sobre los pasos que resultaron ejecutar.
3. **Saltear no es fallar**: imagen faltante, adaptador faltante, una herramienta que respondió *no aplica* — `skipped`, con la frase que lo arreglaría.
4. **Desconocido no es limpio**: una respuesta vacía sin escaneo detrás es una pregunta.
5. **Revocable sin cooperación**: el worker mata al hijo, el proxy corta el flujo. Ninguno le pide permiso al agente.

### Qué no es

- no es un SaaS, ni un servicio multi-tenant;
- no es un pentest automatizado — los perfiles web son reconocimiento;
- no es un producto de IA — el modelo lee, propone y está acotado;
- no es un reemplazo de una persona: el agente propone, la plataforma guarda, una persona decide.

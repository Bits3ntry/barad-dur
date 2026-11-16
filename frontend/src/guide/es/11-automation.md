Todo lo que una máquina necesita para hablar con esta plataforma, y el orden en que se configura.

### Identidades de servicio (API keys)

Configuración → **Identidades de servicio** emite keys. Una sola regla decide cómo las tratas: **una API key es owner de toda la organización y saltea los comprobaciones de rol**. Una key no es "un bot con derechos limitados" — es el workspace. Entonces:

- una key por consumidor (CI, worker, MCP, un tablero), nombrada según su consumidor;
- nunca en un perfil de navegador que no entregarías, nunca en un commit, nunca en una captura de pantalla;
- se revoca desde la misma pantalla, de inmediato; la última key activa no se puede revocar, y eso es una protección contra quedarte afuera;
- una key pegada en un chat es una key para rotar.

El uso de cada key aparece en el **Registro de auditoría**, así que "qué consumidor hizo esto" tiene respuesta.

### El CLI local (`barad`)

Tres comandos, sin tablero y sin red:

| Comando | Resultado | Efecto remoto |
|---|---|---|
| `barad scan [path]` | evidencia en `.barad/reports/<project>/<version>/<scan-id>/` | ninguno |
| `barad run [path]` | el mismo escaneo, después sincroniza las integraciones habilitadas | solo lo que configuraste |
| `barad health` | comprobaciones de herramientas, config y endpoint | solo lecturas autenticadas |

```sh
python3 -m venv /tmp/barad-venv
/tmp/barad-venv/bin/python -m pip install .
/tmp/barad-venv/bin/barad health
/tmp/barad-venv/bin/barad scan . --out /tmp/evidence
```

La configuración es un `.barad.yml` opcional en el directorio de invocación; las credenciales son variables de entorno, nunca YAML. `security.json` y `sast.json` pueden contener secretos y extractos de código: quedan solo para el owner.

### El CLI del scanner (`shauron`)

El plano de ejecución, descrito en su propio capítulo: `scan`, `plan`, `surface`, `upload`, `worker`, `agent`, `login`, `ticket`, `runtime`, `tools`, `doctor`. Úsalo cuando la consola no es el driver correcto — CI, una flota, o una ejecución offline que sube después.

### La action de CI

`action/action.yml` en el repositorio de Shauron es una action compuesta; el workflow del repositorio usa el mismo CLI:

```yaml
- uses: actions/checkout@v4
- uses: ./action
  with:
    command: scan   # scan, run or health
    target: .
    config: config/ci.barad.yml
```

Para `run`, pon las credenciales de integración solo en un step o job de confianza. La action emite el ticket **antes** del trabajo lento, instala los motores pinneados y después escanea — así una falla queda registrada como ejecución abandonada y no como una ejecución que nunca existió.

### El servidor MCP

`mcp/` trae `barad-mcp`, que expone el catálogo de herramientas de la propia plataforma a agentes externos (las mismas declaraciones que usa el ejecutor in-process, importadas en lugar de copiadas). Necesita el paquete de la plataforma instalado al lado y una identidad de plataforma. Un cliente MCP actúa como su propio principal — no es una segunda forma de ser owner.

### Webhooks y Slack

Configuración → **Notificaciones** crea **canales de entrega**. Dos tipos: `slack` (una URL de incoming-webhook) y `webhook` (cualquier receptor).

Cada canal se suscribe a eventos, con un toggle por fila:

| Evento | Se dispara cuando |
|---|---|
| `sla.breached` | un hallazgo pasó su fecha límite |
| `advisory.new` | el barrido de advisories creó hallazgos que el workspace no tenía |

Tres mecanismos que explican el silencio que la gente reporta:

- el **secreto de firma se muestra una sola vez**, al crear el canal — cópialo en ese momento;
- la entrega se **deduplica por canal por día**, así que un canal que disparó esta mañana queda callado esta tarde;
- un receptor de webhook dentro de un contenedor tiene que llegar al host por un nombre que pueda resolver (`host.docker.internal`), y un puerto ya tomado por otro listener falla en silencio — el proceso viejo responde, normalmente con un 404.

La **campana** de la consola es el centro in-app y funciona sin ningún canal configurado. Si no te suscribiste a nada y no esperabas nada, está bien.

### Email

Configuración → **Entrega** configura el correo saliente del deployment: host, puerto, remitente, usuario, contraseña, STARTTLS. Un solo relay sirve las invitaciones y todas las notificaciones por email, y por eso es una configuración de deployment y no de organización. La pantalla siempre dice qué fuente está en efecto (`database`, `environment` o `none`) y si hay una contraseña guardada — la contraseña en sí es write-only.

### Jira

La configuración lleva `JIRA_BASE_URL` y `JIRA_TOKEN` a nivel deployment; la pantalla **Jira** después lista los vínculos entre hallazgos y tickets, crea uno, empuja un estado y **reconcilia** (vuelve a leer el remoto e informa el desvío). Una configuración faltante se imprime como *Jira not configured*, que es un problema del deployment, no un bug de la consola.

### Hablar con la API directamente

Cada pantalla es cliente de la misma API. Dos llamadas que vale la pena memorizar:

```sh
# health, no auth
curl -s http://127.0.0.1:8090/healthz

# list findings as the workspace
curl -s -H "X-API-Key: $BARAD_API_KEY" \
  "http://127.0.0.1:8090/api/v1/findings?sort=severity&limit=20"
```

El documento OpenAPI lo sirve la propia API (`/docs`), y es la lista autoritativa de rutas — este capítulo es un mapa, no un reemplazo.

### Una automatización mínima, de punta a punta

1. Emite una key nombrada según el consumidor (Configuración → Identidades de servicio).
2. Guardala en el almacén de secretos del consumidor.
3. Apunta el consumidor a la dirección alcanzable de la plataforma — `127.0.0.1:8090` es host-only a propósito, así que un runner de CI en otra red necesita la interfaz bindeada o un reverse proxy.
4. Haz una lectura (`/healthz`, después un listado) antes de escribir nada.
5. Deja el uso de la key en el registro de auditoría dándole un nombre reconocible, y después lee el registro una vez para confirmar que está.

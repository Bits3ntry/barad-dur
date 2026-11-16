Este es el camino más corto desde un workspace vacío hasta un hallazgo que puedas mostrarle a alguien. Lleva alrededor de una hora, y cada paso es una pantalla que puedes abrir desde aquí.

### Paso 0 — Entrar

**La primera vez** (una base de datos vacía), la consola abre en *Configura tu workspace*. Necesitas tres cosas: un nombre de organización, una cuenta de owner (email + contraseña) y un **código de configuración**. El código de configuración es el `BOOTSTRAP_TOKEN` del despliegue — lo tiene quien corre el stack. No es una contraseña y no sobrevive a la configuración.

**Todos los demás días** entras con tu email y contraseña. Factores secundarios opcionales, en el orden en que el despliegue los soporta:

- **Autenticación multifactor** — se configura por persona en Configuración → Mi seguridad.
- **Single sign-on** — si el despliegue tiene un proveedor de identidad, la pantalla de ingreso lo ofrece; primero tienes que escribir el slug de la organización, porque SSO necesita saber a qué workspace estás entrando.
- **Un link de invitación** (`/invite#token=…`) — de un solo uso, resuelve a un asiento con un rol. Alguien con *Administrator* u *Owner* lo manda desde Configuración → Miembros.

Si la barra superior dice **API key** en vez de *Sesión iniciada*, el navegador está hablando con la plataforma usando una clave de servicio. Esa clave actúa como owner del workspace, así que trata el perfil del navegador como una credencial.

### Paso 1 — Decirle a la consola dónde está la plataforma

La **primera ejecución sigue en un recorrido guiado** (`/startup`): workspace y owner, datos de la organización, invita a tu equipo, conecta el código, conecta los tickets, entrar. Cada paso se guarda mientras escribes, así que una recarga retoma donde lo dejaste, y un paso opcional se puede saltear sin fingir que quedó configurado.

Configuración → Cuenta tiene dos cosas: la **URL de la plataforma** y, para automatización, una **API key**. En el stack Docker local la URL está vacía (mismo origen a través de nginx) y una sesión iniciada no necesita clave. Solo pegas una clave aquí cuando el navegador no tiene sesión — por ejemplo, un tablero de solo lectura.

Configuración → Organización es la identidad del workspace: nombre, logo, una frase sobre la organización, su sitio. Es lo que la barra lateral muestra bajo la marca del producto.

### Paso 2 — Declarar el alcance antes que nada

El **Alcance** es la lista de cosas que este workspace tiene permitido mirar. Declarar un objetivo es una declaración de propiedad, no un permiso para escanear — los dos están separados a propósito (ver *Autorización*, más abajo).

Los objetivos vienen en ocho tipos:

| Tipo | Qué cubre |
|---|---|
| `domain` | un hostname, o una regla `*.pattern` |
| `url` | un origen más un prefijo de ruta opcional |
| `ip` / `cidr` | una dirección o un rango |
| `repository` | `owner/name` en el host de código conectado |
| `service` / `api` | un límite interno con nombre |
| `cloud_account` | solo declarativo, sin recolección |

**Las exclusiones siempre ganan** sobre cualquier objetivo que las incluya, y pueden ser patrones. Un alcance bien formado tiene las dos cosas: lo que es tuyo y lo que nunca tienes que tocar aunque resuelva bajo algo tuyo.

### Paso 3 — Crear el proyecto y después sus componentes

Un **proyecto** es una aplicación o un producto. Desde **Proyectos → nuevo proyecto**:

| Campo | Para qué sirve |
|---|---|
| nombre | nombre humano — `Aurea` |
| grupo | la unidad de negocio o el portafolio al que pertenece |
| owner | la dirección de una persona, para responsabilidad |
| slug | la dirección URL: `/projects/aurea` |
| descripción | una frase: qué hace y quién lo usa |

Un proyecto nuevo nunca es un cascarón vacío: se crea con un primer componente. Añade más desde la pestaña *componentes* del proyecto — **Backend**, **Web**, **Mobile** son componentes, y cada uno lleva sus propias versiones, repositorios, entornos, dominios y endpoints.

Crear un componente no cuesta nada y desbloquea el resto:

- **adjuntar un repositorio** — es la autorización en la que se apoya una ejecución de CI, y sin eso no se puede generar ningún pipeline para ese componente;
- **añadir una versión** — `1.8.0`, `main`, un sha de commit; las versiones agrupan builds;
- **añadir entornos, dominios y endpoints** — son la vista propia del proyecto sobre dónde corre.

### Paso 4 — Darles contexto de negocio a los activos

**Activos** es la otra cadena de inventario: todo lo que realmente se observó — dominios, subdominios, URLs, IPs. Tiene cuatro pestañas (lo declarado, lo observado, lo visto en el tiempo y el registro de actividad), y cada fila responde "de quién es esto, cuán importante es, a qué proyecto pertenece".

Dos cosas que conviene saber antes de tocarlo:

- **Asignar un proyecto a un dominio se propaga a sus subdominios**, pero solo a los que no tienen proyecto propio, y solo cuando marcas **con subdominios**. Un clic archiva una fila; el tilde archiva el subárbol. La cantidad que estás por mover la decides tú, no la consola.
- **`last_seen` no es evidencia.** Esa columna es cuándo se escribió la fila. "Cuándo lo observamos por última vez" sale de la observación más nueva.

### Paso 5 — Autorizar el análisis (aquí es donde escanear se vuelve posible)

Declarar un dominio abre un **pedido de autorización**. La declaración pregunta; no responde. Solo **Configuración → Autorizaciones** aprueba, y la aprobación es lo que escribe el registro de alcance que lee el motor de escaneo.

Cuando apruebas, eliges tres cosas:

1. **El nivel** — un paquete de capacidades:

| Nivel | Capacidades | Qué recolecta | Riesgo |
|---|---|---|---|
| escaneo simple | verificación pasiva + activa | IPs, el certificado que sirve, las tecnologías que revela la respuesta | abre una conexión TLS y lee la respuesta |
| escaneo avanzado | + análisis de vulnerabilidades | todo lo que hace basic, más puertos abiertos, servicios y versiones | activo pero no intrusivo: banners, headers, puertos |
| red teaming | + pruebas intrusivas | todo lo que hace advanced, más descubrimiento de contenido | más pedidos, incluso a rutas que no existen |

2. **El alcance que cubre la autorización** — el host, o el host y todo lo que está debajo. "Todo lo que está debajo" significa el apex más `*.host`; esa definición es de la API, no de la pantalla.
3. **Una expiración** — horas por defecto, porque una autorización sin final es una política que nadie volvió a revisar.

Una autorización vencida o más angosta es el motivo más común por el que un escaneo se niega a ejecutar mientras la pantalla dice que el activo está autorizado. Ambas leen la misma fila: compara el principal, el objetivo y la expiración antes de dudar de la consola.

### Paso 6 — Ejecutar el primer escaneo

Dos puertas, la misma cola:

- **Orquestación → nuevo schedule** — trabajo recurrente.
- La **página del activo → escanear** (también en la pantalla de una ejecución) — una ejecución única y deliberada. El diálogo hace tres preguntas: qué activo, qué perfil y para qué es esta ejecución (una nota de trabajo opcional). La lista de perfiles está filtrada a lo que este plano puede ejecutar realmente, y un perfil que no puede ejecutar aquí dice por qué en vez de desaparecer.

La consola solo **encola**. Una ejecución se ejecuta cuando un worker está vivo, la reclama y pasa la reautorización al reclamarla. Si no pasa nada, la respuesta está en *Solución de problemas*, no en la UI.

Lo que deberías ver: la ejecución aparece de inmediato como `queued`, pasa a `leased`, después reporta sus pasos y termina con una **cobertura** (`full`, o `partial` con la frase que explica qué se salteó). Los perfiles de recon producen **ningún hallazgo** a propósito — producen observaciones. Ese es el producto, no una pantalla vacía.

### Paso 7 — Meter un build

Los builds son listas de materiales de software. No se tipean a mano: llegan de un escaneo.

- **Desde CI**: construye un pipeline (ver *Pipelines y entrega*) y sube un commit. La CI anuncia el commit, acuña un ticket, escanea y sube.
- **Desde una laptop**: `barad scan .` escribe la evidencia localmente; del lado de la plataforma queda la subida (la API acepta un documento CycloneDX JSON como cuerpo crudo).
- **Desde la API**: `POST /api/v1/sbom` con el documento como `application/octet-stream` (no JSON-encoded) y `project` / `component` / `version` en la query.

El mismo documento dos veces no cambia nada: la ingesta es idempotente por `(project, version, content hash)` y responde `unchanged`. Volver a subir un archivo para “reparar” filas guardadas es un callejón sin salida — la reparación ocurre en el camino de lectura.

### Paso 8 — Triar tu primer hallazgo

**Hallazgos** es la lista de trabajo. Abre una fila: severidad, qué es, dónde, su evidencia y su historial. Después decide — es lo único que la plataforma le pide a un humano, y guarda la respuesta:

- poner un **estado** (abierto → reconocido → en progreso → resuelto, o falso positivo / riesgo aceptado),
- darle un **owner**,
- y si llegaste desde una ejecución, la decisión se añade a la línea de tiempo de esa ejecución, así que seis meses después la ejecución todavía dice quién miró y qué concluyó.

**Mi trabajo** son las mismas filas, filtradas a tú: asignaciones, pedidos, tareas y aceptaciones con sus fechas límite.

### La checklist que lee datos en vivo

Configuración → **Guía de configuración** no es un tutorial; es una página de estado. Seis pasos, cada uno leyendo un conteo real de la API:

| Paso | Está hecho cuando |
|---|---|
| Alcance | existe al menos un objetivo o una exclusión |
| Proyectos | existe al menos un proyecto |
| Activos | al menos un activo tiene contexto de negocio |
| Autorización | existe al menos una autorización |
| Hallazgos | al menos un componente está en seguimiento |
| Ciclos | se creó al menos un ciclo CTEM |

Una organización vacía muestra `0 of 6` — esa es la respuesta correcta, no un bug.

### Para dónde seguir

- *Conceptos* si alguna palabra de este capítulo era nueva.
- *Inventario* para entender qué contiene realmente un build.
- *Superficie de ataque* para el ciclo completo declarar → autorizar → escanear → observar.
- *Orquestación* cuando una ejecución no avanza.

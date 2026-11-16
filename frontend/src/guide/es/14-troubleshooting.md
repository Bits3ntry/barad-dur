El orden aquí es deliberado: primero el comprobación más barato, y la mayoría de estos casos se responden sin tocar código.

### Una lista está vacía

| Primer comprobación | Después |
|---|---|
| ¿Hay un filtro aplicado? La tabla imprime `N of M`. | límpialo |
| ¿El estado vacío dice *nunca analizado* o *nada encontrado*? | si dice nunca analizado, el trabajo no se ejecutó — ve a Orquestación |
| ¿La pantalla lee los datos que piensas? Un `.count` en una tarjeta de resumen puede contar un conjunto distinto que la tabla de abajo | lee el total desde la API con el mismo filtro |

Una tabla vacía en este producto es una **pregunta**. Se vuelve respuesta solo cuando se ejecutó un escaneo y su cobertura es `full`.

### Un escaneo no produjo hallazgos

Los perfiles de recon no producen hallazgos. Su salida son observaciones: DNS, certificado, headers, tecnologías, puertos, servicios. Abre la **página del activo** y la evidencia de la ejecución, no la tarjeta de hallazgos. Si la ejecución fue un escaneo de código o de supply chain, lee su cobertura — una ejecución `partial` examinó menos de lo que prometía el perfil, y el motivo está impreso.

### Una ejecución queda `queued` y no se mueve

Lee cuatro campos juntos: `status`, `attempts`, `worker_id`, `error`.

- `attempts: 0` y `worker_id: null` → **nadie la tomó.** O no hay ningún worker vivo, o ningún worker anuncia una capability que el job necesita. El scanner no es el sospechoso.
- Prueba el claim desde Orquestación contra un worker vivo y lee la respuesta: un claim vacío puede ser un **rechazo** que trae un `reason`.

### Una ejecución queda `leased` para siempre

Un worker la tomó y murió. Reencolala (`queued`, `worker_id = null`, lease limpio) y deja que el próximo claim la tome. Los pasos de la ejecución quedan; no se pierde nada salvo el lease.

### Un worker responde `409 worker heartbeat is stale`

Late demasiado poco. Un worker late antes de cada claim; uno que se registró y dejó de latir queda stale a los pocos minutos y sus claims se rechazan. Un worker cuyo latido falla debería retirarse con el motivo en lugar de reclamar a ciegas — si sigue reclamando a ciegas, todas las ejecuciones parecen congeladas.

### Una autorización está aprobada pero el plan dice `not_authorized`

En este orden:

1. **Objetivo** — ¿el host (o el wildcard `*.host`) está dentro del alcance de la autorización?
2. **Vencimiento** — ¿ya expiró?
3. **Nivel** — ¿el perfil necesita una capability que el nivel no incluye? (Deep recon necesita `intrusive_testing`; escaneo simple no la tiene.)
4. **Principal** — una aprobación desde la consola registra `console`, un plan pregunta como el `collector`. La plataforma acepta sus dos propios principals; un plan que nombra cualquier otra cosa deniega por defecto, que es el comportamiento buscado y no el bug.

### `429` al crear una ejecución

El techo de cola en Configuración → Runtime. Sube el techo o espera a que la cola se vacíe. Los topes por zona y por org se comportan distinto a propósito: dejan la ejecución `queued` en lugar de rechazarla.

### El mismo build subido dos veces no hizo nada

Correcto. La ingesta es idempotente sobre `(project, version, content hash)` y responde `unchanged`. La reparación ocurre en el camino de lectura; volver a subir los mismos bytes no repara filas.

### La consola muestra una versión vieja después de un deploy

Una navegación solo por fragmento puede conservar el documento anterior. Navega con un query string después de una ruta real (`/orchestration?ui=2`) o recarga ignorando la caché, y después confirma que el hash del bundle cargado coincide con el archivo que se sirve. Concluir "el deploy no entró" desde un bundle viejo es un diagnóstico entero equivocado.

### Un link cae en el panel

Solo `/projects…`, `/pipeline`, `/orchestration` y `/invite` son rutas reales. Todo lo demás es `#key`. `#findings` funciona; `/findings` cae en silencio. Mira la miga: `barad-dûr / dashboard` significa que la ruta no resolvió.

### La app entera queda en blanco

Un crash de render deja `#root` en blanco y parece un bug de ruteo: HTTP 200, ningún error visible. Recarga capturando el error una vez y después reporta el stack — ese es el camino más rápido, y casi siempre es un state leído antes de inicializarse.

### Un certificado muestra "unknown issuer · no expiry"

Eso es una **falla de confianza renderizada como certificado**. Una sonda TLS que falla la verificación guarda un error, y una pantalla que infiere confianza desde campos vacíos lo esconde. El estado de confianza y su motivo son los campos a leer; el arreglo está aguas arriba (hostname, intermedio, vencimiento).

### `Jira not configured`

Al deployment le faltan `JIRA_BASE_URL` / `JIRA_TOKEN`. Nada en la consola puede suplirlos.

### Los canales están en silencio

Comprueba, en orden: ¿el canal está suscrito al evento que esperas? (las suscripciones son por evento); ¿ya entregó hoy? (la entrega se deduplica por canal por día); ¿el receptor resuelve desde dentro de un contenedor? (`host.docker.internal`); ¿el puerto que esperas es realmente tuyo? (un listener viejo que responde 404 parece una integración rota). Usa la acción **test** del canal antes de depurar el evento.

### La IA se detiene antes

- `stopped_budget` → se alcanzó un tope mensual. El tope que la detuvo está nombrado en la ejecución.
- `429` en una llamada al modelo → el techo de tokens de la propia misión, no un fallo pasajero. No lo reintentes como si fuera transitorio.
- `503` → el workspace no tiene proveedor configurado, o el seleccionado está deshabilitado.

### Las invitaciones no llegan

Configuración → Entrega: si la fuente de correo es `none`, no se envió nada. En ese caso la pantalla de Miembros te da la URL de invitación — pásala y dilo, en lugar de pedirle al invitado que revise spam por un mail que no existe.

### La consola no llega a la plataforma

`Failed to fetch` en todas las pantallas normalmente significa que la **URL de plataforma** guardada apunta a un lugar que el navegador no puede llamar (por ejemplo `http://127.0.0.1:8090` desde una página servida en otro origen). En el stack provisto, dejala **vacía**: nginx proxea `/api` en el mismo origen, y un origen explícito convierte una sesión que funcionaba en una falla de CORS que parece una pantalla rota.

### "7 workers online" cuando hay uno corriendo

La tabla de workers cuenta **filas**, y los registros de prueba dejan filas atrás. Una fila de worker está `online` solo mientras late, y el conteo de réplicas configurado del deployment se muestra al lado del vivo exactamente por eso. Confía en el heartbeat, no en el conteo de filas.

### Reportar algo que sí está roto

Incluye: la pantalla (y la dirección en la barra), qué esperabas, qué viste, el id **completo** de la ejecución/hallazgo/activo, la hora UTC y el workspace. Con esas cinco cosas un defecto es reproducible; sin ellas es una captura de pantalla. Una regla: cuando reportas una ejecución que no arrancó, no reinicies el daemon ni la reencoles antes — el estado que destruirías es la evidencia.

**Orquestación** es la respuesta de la consola a tres preguntas, en este orden: qué va a ejecutar solo, quién lo va a ejecutar, y qué ya se ejecutó. Cada ejecución del workspace — los barridos propios de la plataforma, los jobs en cola, y los que arrancó una terminal — aparece aquí como un solo registro.

Si lees una sola cosa en esta pantalla, lee la columna **origin**. `internal`, `worker` y `cli` son tres radios de impacto distintos y tres personas distintas a las que llamar a las 3 de la mañana.

### 1. Qué está agendado

Dos tipos de agenda, mostrados juntos porque para quien lee son la misma promesa:

- **tus agendas** — "este escaneo, sobre este activo, cada N minutos". Cada fila imprime su cadencia, la próxima ejecución y las acciones que puedes tomar sobre ella (prender o apagar, ejecutar una vez);
- **los barridos propios de la plataforma** — el reloj de avisos y el matching de CPE de runtime. Son escaneos `internal`: no son jobs que se le entregan a un worker, son trabajo que hace el propio proceso de la API.

Un barrido interno también se puede forzar desde su fila. La respuesta te dice si **tocaba** o no: un job que decide su propio intervalo responde `not_due` y no escribe nada, porque el historial no es un latido — un tick `not_due` no es una ejecución y no debería aparecer como una.

### 2. Quién lo corre

La tabla de workers es un recuento de **filas**, no de procesos vivos, así que imprime lo que la fila declara y lo que dice el latido:

| Columna | Significa |
|---|---|
| worker | el nombre registrado |
| slots | `max_concurrent` — cuántas ejecuciones puede sostener |
| capabilities | el CSV de capacidades que anuncia |
| status | `online` mientras late; cualquier otra cosa está vencida |

Un worker se declara **obsoleto** después de un par de minutos sin latido, y los claims de un worker obsoleto se rechazan con `409 worker heartbeat is stale`. Eso es el diseño, no un bug: un worker que se registró una vez y dejó de latir no debe seguir tomando trabajo. Si la lista no muestra nada vivo mientras una ejecución espera en la cola, la respuesta casi siempre es "el proceso no está corriendo", no "el escáner está roto".

**Registrar un worker aquí no arranca uno.** Esta fila es la identidad que usa un proceso; el proceso en sí es `shauron worker`, que en el stack provisto corre como el servicio `shauron-worker`. Un registro es una fila, y una fila no puede ejecutar nada.

### 3. Qué ya se ejecutó

El registro es cada ejecución, de la más nueva a la más vieja, paginado, filtrable por origen. Cada fila imprime estado, cuándo, qué tipo de trabajo, el objetivo y la duración. Una ejecución que lleva más de una hora en `running` se reporta **obsoleta** — un proceso muerto no debe dejar un spinner para siempre, y no hace falta ningún cron job para decirlo.

### El protocolo de claim, en palabras simples

El ciclo de un worker son tres llamadas: **beat**, **claim**, **report**.

1. `POST /orchestration/workers/{id}/heartbeat` — "estoy vivo".
2. `POST /orchestration/jobs/claim` — "dame trabajo". La plataforma vuelve a autorizar los objetivos del job con el principal del job, verifica que las capacidades del worker sean un **superset** de lo que el job necesita, aplica los topes de zona y de org, y después lo arrienda.
3. Reporta los pasos a medida que pasan, y después termina.

Dos consecuencias que vale la pena conocer:

- **Un claim vacío puede ser un rechazo.** La respuesta puede ser `{"data": null, "rejected": {"job_id", "reason"}}` — la cola tenía algo y el motor dijo que no. Leer eso como "no hay nada en cola" esconde una decisión de autorización detrás de un worker ocioso.
- **Un worker que muere a mitad de una ejecución la deja `leased`** con su id todavía pegado, y el claim siguiente responde `409 worker at concurrency limit` mientras la ejecución no se mueve nunca. El arreglo es volver a encolarla (`status=queued`, `worker_id=null`, `lease_expires_at=null`) y reclamar de nuevo.

### Concurrencia y el pool

Configuración → **Runtime** guarda la política que el claim lee en cada pedido:

| Ajuste | Efecto |
|---|---|
| `per_zone` | ejecuciones en vuelo contra un mismo dominio registrable |
| `per_org` | ejecuciones en vuelo en el workspace |
| `per_worker` | ejecuciones que puede sostener un worker |
| `queue_ceiling` | profundidad de la cola; más allí, la creación se rechaza con `429` |
| `min_workers` / `max_workers` / `scale_down_after_s` | cómo se dimensiona el pool online |

El piso es uno a propósito: cero workers y un escáner roto se ven idénticos en todas las pantallas, y eso es lo que alguna vez hizo que una cola sana se leyera como "el escaneo no funciona".

El scaler es un **proceso aparte**; la API publica el objetivo y el scaler lo aplica. La consola muestra el objetivo en solo lectura al lado del conteo en vivo — una app que escala sus propios contenedores es una app sobre la que no puedes razonar.

### Los jobs propios de la plataforma

Los escaneos internos son la mitad de "lo que corre solo" que nadie agendó a mano:

| Job | Qué hace |
|---|---|
| advisory refresh | vuelve a preguntarle a OSV por el build más nuevo de cada proyecto/componente, y refresca KEV y EPSS |
| runtime CPE matching | mapea los runtimes declarados y los tags de imagen a productos de NVD y matchea sus CVE localmente |

Cada ejecución es una fila con sus contadores, su duración y su log, y el log es una puerta en la fila. Configuración → Intelligence es dueña del intervalo, las fuentes y de si el reloj corre o no.

### Encolar un job a mano

El bloque **setup** colapsado al pie de la página guarda las tres cosas que son configuración, no trabajo diario: registrar un escáner, registrar un worker, encolar un job a mano. Un job manual toma un escáner, una capacidad, un principal, un objetivo y un entorno — es cómo pruebas que un camino funciona sin esperar una agenda.

Una ejecución que un operador arranca desde la consola no tiene autorización propia; se registra como override administrativo para que la revalidación del claim no la mate. La excepción es red team: un perfil intrusivo se vuelve a comprobar como el collector incluso detrás de un override, porque el trabajo intrusivo nunca corre solo porque una persona lo dice.

### Los cuatro campos que nombran una falla

Cuando una ejecución no avanza, lee estos juntos antes de tocar nada:

| Lo que ves | Lo que significa |
|---|---|
| `queued`, `attempts: 0`, `worker_id: null`, `error: null` | nadie la reclamó nunca: no hay worker vivo, o ninguno que anuncie la capacidad |
| `leased` con un `worker_id` | un worker la tomó y murió |
| `failed` con un `error` | la plataforma la rechazó — lee el error |
| `429` al crearla | el techo de la cola |
| `409 … stale` al reclamar | el worker dejó de latir |

Ninguno de esos cinco es un problema del escáner, y cuatro se arreglan sin tocar un escaneo.

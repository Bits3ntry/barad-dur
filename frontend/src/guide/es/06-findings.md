Un hallazgo es el único objeto sobre el que la plataforma le pide a una persona que decida. Todo lo demás — inventario, observaciones, ejecuciones — existe para que un hallazgo valga la pena leerse.

### De dónde sale un hallazgo

| Fuente | Tipo de hallazgo | Llega por |
|---|---|---|
| Ingesta de SBOM | un CVE (o un grupo) en un paquete de un build | subida del build, pipeline, CLI |
| reloj de avisos | un CVE publicado **después** de que se escaneó el build | el barrido propio de la plataforma (OSV, KEV, EPSS, NVD) |
| análisis de código | una debilidad (`sast`) o un secreto expuesto (`secrets`) | el escaneo de CI, sobre un checkout |
| ejecución de superficie | una exposición: un servicio alcanzable, un certificado débil, una ruta abierta | las observaciones de una ejecución de recon |
| pentest / manual | un problema validado | la campaña de pentest, o un informe importado |

Un hallazgo se identifica por la cosa que está mal (un CVE, una regla, un sujeto), no por el documento en el que llegó. Dos fuentes que nombran el mismo defecto producen una sola fila.

### Cómo se ordena la lista

**risk = peso de severidad × KEV × EPSS, con tope en 100.** Una vulnerabilidad explotada en el mundo real queda por encima de una teórica aunque las dos digan "alta", y la pantalla explica por qué el orden es el que es. Cuando ordenas distinto, estás eligiendo otra pregunta — `Findings` y `Vulnerabilities` ordenan del lado del servidor, así que un filtro y un orden siempre describen el conjunto entero, no la página visible.

### El triaje es una decisión, y queda registrado

Abre una fila y define:

| Estado | Significa |
|---|---|
| `open` | nadie lo miró, o no se concluyó nada |
| `acknowledged` | visto, aceptado como trabajo, sin empezar |
| `in_progress` | alguien lo está haciendo |
| `resolved` | cerrado por evidencia: una actualización, una rotación, un cambio de código |
| `false_positive` | el escáner se equivocó, y por qué |
| `accepted_risk` | es real, y elegimos convivir con eso |

Además un **responsable** y, en la mayoría de las filas, un **SLA** con fecha límite. Las filas vencidas son las que cuenta el badge del Panel y de las que avisa `sla.breached`.

El triaje puede hacerse desde **la ejecución** que lo produjo, y ahí añade un evento `decision` a la línea de tiempo de esa ejecución. Ese es el punto: seis meses después la ejecución sigue diciendo quién miró y qué concluyó, en lugar de un campo de estado sin autor.

Un hallazgo descartado no desaparece del build al que pertenece. Los builds listan las filas saldadas con `dismissed: true`, porque "lo miramos y lo descartamos" y "nadie escaneó esto" son hechos distintos sobre un build.

### Las pantallas, y la única pregunta que responde cada una

| Pantalla | La pregunta |
|---|---|
| **Panel** | ¿dónde está el parque hoy? |
| **Mi trabajo** | ¿qué es mío, y qué vence? |
| **Hallazgos** | ¿qué necesita una decisión? |
| **Vulnerabilidades** | ¿qué avisos existen, y qué tan graves son en realidad? |
| **Exposiciones** | ¿qué es alcanzable y no debería serlo? |
| **Reglas de priorización** | ¿cómo se calcula la prioridad aquí? |
| **Impacto de negocio** | ¿qué aplicación carga el trabajo abierto? |
| **Regresión** | ¿qué volvió después de que creíamos que estaba arreglado? |
| **Remediación** | ¿cuál es el plan y el ciclo de vida del trabajo? |

**Mi trabajo** se arma con asignaciones, pedidos, tareas y aceptaciones — colas reales de filas reales, nunca un mock estático. Cada cola dice qué es: *asignado a mí*, *esperando mi decisión*, *esperando mi aceptación*.

**Vulnerabilidades** es el catálogo de avisos: KEV y EPSS al lado de la severidad, filtros que llegan desde una tarjeta del panel (`#vulnerabilities::kev=1` abre la puerta de las explotadas en el mundo real), y los builds afectados. Responde "¿este CVE famoso está en nuestro parque?", que es una pregunta distinta de "¿qué hago ahora?".

**Exposiciones** agrupa los hallazgos de alcanzabilidad y los cuenta con honestidad: abiertos, aceptados, resueltos.

**Reglas de priorización** es donde la política de pesos se ve y se edita, e **Impacto de negocio** añade el trabajo abierto por aplicación — contado desde hallazgos, activos y despliegues, así que no puede desviarse de las filas que resume.

### Regresión

Cuando alguien declara un arreglo, la regresión vuelve a probar esa declaración en lugar de creerle. Es la única forma de que un estado "resolved" sobreviva al siguiente escaneo: la misma regla, el mismo objetivo, una ejecución nueva.

### Los estados honestos, en la lista de hallazgos

- **Un 404 crudo no es "no afectado".** Buscar una vulnerabilidad que el workspace no tiene devuelve "ningún hallazgo coincide", que se lee igual que "estás limpio". La API distingue nunca escaneado de escaneado y ausente, y cualquier respuesta automatizada mantiene esa distinción.
- **La cobertura viaja con el hallazgo.** `partial` en la ejecución significa que el parque no se examinó del todo; el hallazgo sigue siendo real, el silencio alrededor no informa nada.
- **Desconocido es un estado, no un color.** Un componente sin feed de avisos para su ecosistema es `unknown`, con el motivo.

### Qué cierra un hallazgo

No un comentario. Tres clases de cierre, y no cierran igual:

1. una **credencial** es explotable ahora y se cierra con rotación — borrar el archivo no revoca la clave, y el historial de git la conserva;
2. un **CVE** se cierra actualizando el componente, cosa que prueba el build siguiente;
3. una **debilidad de código** se cierra cambiando código y volviendo a escanear, cosa que confirma la regresión.

Guardar la clase (CVE de dependencia, credencial, SAST, mala configuración) junto al hallazgo es lo que te permite responder "¿esto está cerrado de verdad?" un año después.

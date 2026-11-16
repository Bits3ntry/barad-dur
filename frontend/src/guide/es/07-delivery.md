La entrega es cómo el escaneo deja de ser algo que una persona se acuerda de hacer. Un **pipeline** anuncia un commit, la plataforma acuña un ticket para él, la CI corre el escaneo, y el build espera el veredicto.

### Qué es un pipeline (y qué no)

Un pipeline es **un archivo en tu repositorio**. La consola te arma ese archivo; no guarda un objeto pipeline que pueda contradecir lo que tu CI corre en realidad. El asistente no crea nada en la plataforma — lee los componentes y repositorios de tu proyecto y escribe un fragmento que tú haces commit.

Si el archivo y la consola alguna vez no coinciden, gana el archivo, porque el archivo es lo que se ejecuta.

### Monta uno: cuatro preguntas, de a una

**Pipelines → nuevo pipeline.**

**1. Dónde corre.** Proyecto, después componente. El componente tiene que tener un **repositorio vinculado** — ese vínculo es la autorización en la que se apoya una ejecución de CI, y sin él cada acción leería un checkout que no existe. La pantalla lo dice en lugar de dejarte montar un archivo roto. Después elige la CI de destino:

| Elección | Resultado |
|---|---|
| detectar desde el repositorio | el fragmento sigue el proveedor del remoto |
| GitHub Actions / Gitea Actions / GitLab CI | la sintaxis exacta de esa |
| cualquier otra CI (script portable) | un script de shell que cableas tú |

**2. Qué revisa.** Elige una o más **acciones**. Una acción es un paquete de tareas con nombre:

| Acción | Tareas | Sale de la máquina | Responde |
|---|---|---|---|
| Revisión de código fuente (`code`) | `sast`, `secrets` | no | ¿qué hay en este commit? |
| Dependencias y configuración (`supply-chain`) | `sbom`, `runtime`, `misconfig`, `secrets` | no | ¿de qué dependemos, y qué está mal configurado? |
| Secretos verificados (`secrets-verified`) | `secrets` (verificación en vivo) | **sí** | ¿esta credencial sigue viva? |
| Superficie de ataque (`web-surface`) | subdominios, DNS, TLS | **sí** | ¿qué publicamos sin saberlo? |

Una acción que sale de la máquina está marcada `console only` en el asistente y no se puede elegir para un push, porque un ticket de push nunca puede pedir trabajo de red. Eso no es precaución — es la misma regla que aplica el motor cuando valida el ticket.

Dos acciones pueden pedir la misma tarea (`secrets` vive en dos de ellas). Cuando pasa, el escáner corre dos veces, y el asistente lo dice antes de que lo descubras en los contadores.

**3. Cuándo corre.** `on every push`, `on every pull request`, `on demand`. Elige según lo que cambió, no por costumbre: un cambio de código fuente merece el conjunto barato (sast, misconfig, secrets), un cambio de manifiesto o lockfile merece `supply-chain`, y volver a escanear dependencias cuando no cambió ninguna dependencia no compra nada y cuesta una descarga de base de datos.

**4. El archivo.** El asistente imprime la ruta y el contenido, listos para copiar. Commitealo. Añade la URL de la plataforma, y la clave o token que tu CI ya guarda como secreto — nunca como una variable plana que un pull request pueda imprimir.

### La primera ejecución, de punta a punta

```
developer pushes
   └─ CI runs the generated file
        ├─ ticket announced (before the slow work)
        ├─ engines installed and verified against their pinned hashes
        ├─ the scan writes artefacts into the run directory
        └─ evidence uploaded: steps, then observations, then finish
   └─ Pipelines shows a commit row with coverage and a verdict
```

Acuñar el ticket **antes** del trabajo lento es deliberado: hasta que el ticket existe la plataforma no tiene nada que mostrar, así que una instalación de motor fallida se vería como una ejecución que nunca ocurrió en vez de una registrada como abandonada. Los dos son hechos observables; un hueco silencioso no.

### Leer Pipelines

Cada fila es un commit: repositorio, componente y versión resueltos, sha del commit, cobertura, estado del escaneo, y los hallazgos que produjo, con un veredicto que falla cerrado. Las filas sin hallazgos no son filas vacías — dicen si no se encontró nada o si no se miró nada.

Un commit que no se puede atribuir a un componente queda visible como *necesita atribución* en lugar de volverse un release de todo el producto. Esa fila es trabajo, no un error.

### Puertas de calidad

**Puertas de calidad** convierte hallazgos en una decisión sobre un build. Una política nombra qué bloquea:

- CRITICAL/HIGH de una regla que **prueba** un defecto (una regla que solo audita, como "esta llamada existe", puede avisar pero no debe bloquear — seis aciertos sobre código correcto es cómo se apaga una puerta);
- cualquier credencial expuesta, forzada a CRITICAL sin importar cómo la llamó el motor: la rotación es el único cierre, y es urgente por definición;
- un CVE que tiene versión con arreglo. Un CVE sin arreglo no es bloqueable — hoy no hay nada que hacer, y bloquearlo le enseña a la gente a saltear la puerta.

Pon en la allowlist los fixtures de test de forma explícita. Cada secreto que produjo un repositorio real vivía en `tests/`.

### Pentests

**Pentests** guarda el trabajo a nivel de campaña: un encargo acotado con su propio alcance y evidencia, para los casos en que una persona ataca la aplicación y la salida es un informe en lugar de un artefacto de escaneo. No reemplaza el ciclo automático; es donde se registran las partes que necesitan criterio.

### Regresión

**Regresión** vuelve a probar los arreglos. Un estado `resolved` es una declaración; la regresión es la ejecución que puede contradecirla, sobre la misma regla y el mismo objetivo.

### Jira

**Jira** vincula hallazgos con tickets y los mantiene sincronizados en las dos direcciones: la pantalla lista los vínculos, puede crear uno, puede empujar un estado, y tiene un botón **reconcile** que vuelve a leer el lado remoto e informa desvíos. Si dice *Jira not configured*, al despliegue le faltan `JIRA_BASE_URL` y `JIRA_TOKEN` — es un ajuste del despliegue, no algo que la consola pueda arreglar.

### Cuando un pipeline no hace lo que esperas

Ordenado por cuántas veces es la respuesta:

1. **El job se queda en 0s, esperando.** No se despachó nada: ningún runner anuncia esa etiqueta, o está registrado pero offline. Un job en cola nunca contacta a la plataforma, así que "no llegan pedidos" no dice nada sobre la red.
2. **Se rechaza la llamada de anuncio.** Prueba la URL de la plataforma desde la red del propio runner — una plataforma atada a `127.0.0.1` es invisible a propósito para un contenedor de job. `401` en lugar de `000` es la buena señal: el camino está abierto y solo falta la credencial.
3. **El escaneo corre y no sube nada.** Revisa el ticket, después la cobertura de la ejecución — un proveedor que falló mientras otro entregó mantiene la tarea viva y nombra la falla en la evidencia.
4. **El commit cayó en el proyecto equivocado.** La atribución usa la URL canónica del remoto y el vínculo del componente, no una suposición a partir del nombre del repositorio.

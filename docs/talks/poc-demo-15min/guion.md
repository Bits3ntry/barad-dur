# DEMO — BARAD-DÛR EN 15 MINUTOS

**Audiencia:** técnica (seguridad, platform, CTO). **Formato:** demo en vivo sobre la consola.
**Objetivo:** que se lleven una sola idea — *la IA no es una capa que adivina: es una capa que
razona sobre datos que ya tienen cadena de custodia.*

**La tesis, en una frase (la decís a los 40 segundos y no la repetís hasta el cierre):**

> "Barad-dûr no es un scanner con una consola. Es la cadena de custodia de lo que sabemos sobre
> nosotros. La IA no agrega una fuente nueva: lee esas mismas filas, y cuando no le alcanza dice
> `unknown` con el borde que falta."

**La regla de la demo:** cada pantalla que mostrás tiene que probar algo que la anterior no probaba.
Si una pantalla no prueba nada nuevo, ✂ se corta.

---

## 1. Qué tiene que existir antes de subir al escenario

Una sola organización. Dos cadenas — porque son las dos que se cruzan en el acto de impacto y en la IA:

| Cadena | Qué la alimenta | Qué prueba |
|---|---|---|
| **Software** | proyecto real con SBOM (`barad run` o upload manual) + un deployment a PRO | componentes, builds, CVEs, impacto |
| **Superficie** | juice-shop con nombre propio (no `localhost`/IP) escaneado con `recon.simple` desde el worker | observaciones atribuidas: DNS, TLS, headers, tecnología, puertos |

**Checklist de ensayo (la noche antes, no en el escenario):**

- [ ] API y consola arriba (`bash scripts/local-up.sh`), `healthz` verde.
- [ ] Asset de juice-shop con **observaciones de hoy**: IPs, certificado (con vencimiento), tecnologías, puertos.
- [ ] Asset sin observaciones a mano — sirve para el contraste "sin cobertura ≠ limpio".
- [ ] Proyecto con build + deployment a producción, y al menos **un finding con `proof_request` cargado** (es el que Angmar va a reproducir).
- [ ] Un target **fuera** del grant: el rechazo es parte del guion, no un accidente.
- [ ] Proveedor de IA configurado. Si no querés depender de la red: preset **ollama** (no pide key).
- [ ] Un finding con CVE **conocido** para la pregunta de Palantír, y uno **sin evidencia suficiente** para mostrar el `unknown`.
- [ ] Ventana del navegador con los cinco hashes ya abiertos en pestañas (abajo están).

---

## 2. Guion minuto a minuto

**✂ = corte de emergencia.** Con los tres cortes entrás en 10:00 sin perder el hilo.

| Reloj | Pantalla (`#hash`) | Qué hacés | La frase que abre el bloque | Qué queda probado |
|---|---|---|---|---|
| **0:00** | `#dashboard` | Nada. Manos quietas. | "Esto responde cuatro preguntas: qué tenemos, qué le falta, qué importa y **quién lo decidió**." | el marco |
| **0:02** | `#ctem` — Resumen del ciclo | Recorrés las cinco fases. Leés un estado **`partial`** y su motivo. | "Un ciclo no está sano porque la tabla esté vacía. Cada fase se deriva de conteos que existen." | CTEM puro, no un menú |
| **0:03** | `#scope` + `#grants` — Alcance / Autorizaciones | Mostrás el target declarado, después el grant aprobado con su nivel y vencimiento. | "Declarar un dominio no es permiso para tocarlo. El grant es lo que habilita." | autorización de verdad |
| **0:05** | `#assets` — Activos | Un asset observado: IPs, certificado y su vencimiento, tecnologías, puertos. Después el asset **sin observaciones**. | "Mirá lo que dice este: *sin cobertura*. No dice limpio. Esa diferencia es el producto." | unknown ≠ clean |
| **0:07** | `#orchestration` — Orquestación | Un job, su worker, el latido, el lease, la cancelación. | "La plataforma no escanea: compone. El worker reclama, late, y si el latido falla se retira." | el plano de ejecución |
| **0:08 ✂** | `#surface::<run_id>` — Ejecución de superficie | El flow por pasos: dns → tls → headers → technology. Un paso `partial` con su motivo, un step con 0 observaciones pero con cobertura declarada. | "El flujo es el producto: quién lo corrió, con qué motor y versión, y por qué se cortó." | atribución y cobertura honesta |
| **0:09** | `#chat` — Asistente | Pregunta 1 (abajo). Abrís el finding que cita. | "Le pregunto si estamos afectados. No me contesta con un párrafo: me contesta con filas y la edad de cada una." | la IA lee el estado, no adivina |
| **0:10** | `#chat` · misma sesión | Pregunta 2 (el borde). | "No le alcanza. Y no me dice 'no afectados': me dice **qué arista falta** para saberlo." | el `unknown` es una respuesta |
| **0:11** | `#chat` · Pregunta 3, sobre un finding con PoC | Aparece el botón **Validar en campo** → click (manda `@angmar validá el impacto de <id>`) → la respuesta propone la misión → botón **aprobar** → "Misión aprobada — el worker la toma en segundos". | "La IA no ejecuta: **propone**. Esos botones salen de un vocabulario cerrado y cada uno se valida contra el estado antes de dibujarse. El de aprobar solo aparece si la misión existe y está esperando a una persona." | la propuesta también tiene puerta |
| **0:12** | `#missions` + `#finding::<id>` (pestaña **Traza**) | Quién lo autorizó, el carril, el presupuesto, y los eventos en orden: herramienta → observación → decisión. Los **gates** y las repeticiones. Cierra en `usable · reproducido` (o en el rechazo). | "Esto es lo que lo vuelve usable: no el texto del modelo, la cadena." | validar una PoC, con firma |
| **0:12b ✂** | `#missions` → Nueva misión | Si querés el rechazo en pantalla: creá la misión con un target fuera del alcance. | "Se rechaza acá, no después: ampliar alcance es una misión nueva, nunca una tarea nueva." | el sobre manda |
| **0:13** | `#ai-runs` — Ejecuciones IA | Una corrida cerrada: perfil, pasos, tokens, costo **o `precio desconocido`**, `cortada por presupuesto`. | "Cada pregunta es un recibo: qué pregunté, qué leyó, cuánto costó y por qué se cortó." | la IA cuesta y se audita |
| **0:14** | `#settings` → MCP | El panel: identidad, dirección, catálogo. Después el cliente externo (Claude Code/Codex/Cursor) con la misma pregunta, y de vuelta acá: la corrida quedó registrada. | "El mismo catálogo, por otro puerto: **una sola declaración de herramientas**, dos transportes. Y la clave es la mía — la plataforma ve a la persona, nunca a una identidad de servicio." | MCP |
| **0:15** | — | Cierre de tres frases (abajo). | — | — |

### Las preguntas exactas (probadas en ensayo, no improvisadas)

1. **Afectación:** "¿Estamos afectados por `CVE-XXXX-YYYY`? Decime en qué deployment, con qué
   evidencia y qué tan vieja es." → esperado: `affected | not_affected | unknown`, **por deployment**,
   con las aristas citadas. Si la respuesta nombra un id, abrilo en vivo.
2. **El borde:** una pregunta sobre un componente que está en el inventario pero **sin deployment
   registrado**. → esperado: `unknown` + la arista que falta. **No** un "no afectados". Si igual lo
   dice, es el hallazgo de la charla: un tablero que nunca dice `unknown` está mintiendo.
3. **Validación:** sobre un finding con PoC cargada, pedí "¿esto está reproducido? ¿qué falta para
   volverlo usable?" → la respuesta ofrece **Validar en campo** y después **aprobar**.
4. **Búsqueda (opcional, ✂):** "¿Qué hallazgos críticos de `<proyecto>` siguen abiertos y sin
   prioridad asignada?" → una lista corta, no un ensayo.

> Nota de honestidad para el escenario: el chat corre como **Palantír** (el analista). No se elige
> perfil desde la pantalla: `@nombre` es lo que dirige la pregunta a un agente. Angmar y Morgoth
> existen como **perfiles de misión** — ahí sí se eligen, porque abren carriles distintos.

---

## 3. Cierre (15 segundos, de memoria)

1. "Las dos cadenas —un CVE en un build y un servicio expuesto— se encuentran en la misma consola."
2. "El modelo razona, la plataforma decide, Shauron ejecuta. El texto del modelo **no es evidencia**."
3. "Y cuando no sabe, lo dice. Un tablero que nunca dice `unknown` está mintiendo."

---

## 4. Lo que NO prometés

Decilo vos antes de que lo pregunte alguien del público:

- **No es un pentest automático.** El perfil web es reconocimiento; lo intrusivo pide grant y aprobación.
- **No reemplaza al humano.** El agente propone; una persona decide. Cada decisión queda en la misma línea de tiempo.
- **No hay vector store.** El estado es estructurado — tablas, purls, CVEs: la recuperación es una consulta con paginado, no una búsqueda por similitud.
- **La IA es una capa interna**, con la clave del operador, presupuesto por corrida y sin salida a red desde el modelo.

---

## 5. Si algo se rompe (tenelo impreso)

| Síntoma | Causa probable | Qué decís / qué hacés |
|---|---|---|
| El chat contesta un error de proveedor | key vencida o modelo mal escrito | preset **ollama** y seguís: "corre local, cero red" |
| El worker no reclama el job | key del worker o latido caído | lo mostrás como estado honesto: `#orchestration` dice que no late |
| Todo sale "fuera de alcance" | grant vencido o exclusion | ese es el bloque 0:03, no lo saltees: "por eso existe el grant" |
| El asset está pelado | el recon es de ayer o no corrió | `#surface`: "cobertura de ayer 19:04, subida offline" — sigue siendo cierto |
| Los feeds (KEV/EPSS) no responden | entorno sin salida | evitá preguntas de intel y decilo: "esta instancia está en loopback" |
| Quedan 3 minutos y falta todo | — | ✂ cortás superficie y MCP; te quedás con el inventario, Palantír + Angmar y `#ai-runs`. Es el 80% del mensaje |

---

## 6. Números (estructurales: no dependen del día)

- **4 preguntas** — qué tenemos, qué le falta, qué importa, quién lo decidió.
- **2 cadenas** — inventario de software (proyecto → componente → versión → build) y de superficie (asset → observación → hallazgo).
- **3 perfiles de IA** — Palantír lee · Angmar valida · Morgoth descubre y explota (con grant). Son promesas sobre lo que el sistema **no** hace.
- **1 catálogo, 2 transportes** — el chat y el MCP renderizan la misma declaración de herramientas.
- **5 fases CTEM** — scoping, discovery, prioritization, validation, mobilization. Ninguna se reporta sana por estar vacía.
- **El texto del modelo no es evidencia** — lo que no se puede rastrear a un `finding_id`/`asset_id`/observación se muestra como hipótesis.

> Los conteos del estado (assets, componentes, findings) **no los recites**: señalá el número en
> pantalla y decí "esto es lo que hay hoy en esta instancia". Un número memorizado que no coincide
> con la pantalla te cuesta toda la charla.

---

## 7. Pestañas a dejar abiertas antes de empezar

```
#ctem
#scope
#assets            (dejar seleccionado el asset observado)
#surface::<run_id>
#chat
#missions
#finding::<id>     (el que Angmar va a reproducir — abrir en la pestaña Traza)
#ai-runs
#settings          (sección MCP)
```

Origen de este guion: `docs/barad-dur-y-shauron.md` (división y contrato),
`docs/planning/ai-harness-and-mcp.md` (decisiones D1–D18 de la capa de IA),
`docs/planning/shauron-surface-scans.md` (§8b, visibilidad del run).

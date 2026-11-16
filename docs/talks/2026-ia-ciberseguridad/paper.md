# Ya no hace falta ser sofisticado

**IA y ciberseguridad: nuevos modelos, nuevas amenazas y nuevas defensas.**

**Paper de trabajo para una charla de 50 minutos · 2 oradores**

> Documento de producción. Cada bloque trae el texto para decir, lo que se muestra en pantalla, la transición y qué recortar si el reloj aprieta. Las marcas `[S1]`…`[S12]` remiten a la tabla de fuentes del final: ningún número de esta charla está sin origen.

---

## Ficha

| | |
|---|---|
| **Título** | Ya no hace falta ser sofisticado |
| **Subtítulo** | IA y ciberseguridad: nuevos modelos, nuevas amenazas y nuevas defensas |
| **Duración** | 47 min de charla + 3 min de buffer para preguntas |
| **Oradores** | **[A] Santiago Andrade** (construye Barad-dûr y Shauron) · **[B] David Barros** (estado del arte y amenazas) |
| **Audiencia** | Desarrolladores, security engineers, CISO/management técnico. Mezcla: no asumir que todos hicieron un pentest, no asumir que ninguno leyó un CVE |
| **Formato** | Charla con demo en vivo y plan B grabado. 39 slides, ninguna con más de 12 palabras |
| **Promesa** | Al final tienen un modelo mental de qué cambió, qué no, y cinco decisiones concretas para el lunes |

## Abstract

La inteligencia artificial está transformando el panorama de la ciberseguridad. En esta charla repasamos el estado actual de la IA, desde los modelos frontier hasta el auge de los modelos chinos de pesos abiertos, y cómo su ejecución en hardware local está democratizando el acceso a estas tecnologías.

Analizamos cómo estos avances están impulsando nuevos flujos de trabajo autónomos y cambiando el mundo de la ciberseguridad, desde el descubrimiento de vulnerabilidades y el Bug Bounty hasta su aprovechamiento por parte de los ciberdelincuentes. Todo con ejemplos y casos reales, y con una segunda mitad dedicada a lo que sí funciona para defenderse: evidencia, alcance autorizado y agentes con límites. Barad-dûr y Shauron —la plataforma y el plano de ejecución que construimos— se usan como caso concreto, no como folleto.

## Tesis

**La IA no cambió la clase de vulnerabilidades. Cambió su economía.**

El costo marginal de *intentar* cayó a casi cero: encontrar, probar, encadenar, reintentar y documentar dejó de consumir el recurso escaso. Y con eso se rompieron tres supuestos sobre los que está construida casi toda la defensa:

1. **Que la sofisticación identifica al atacante.** Un estudiante de grado con un framework público opera como un equipo estatal.
2. **Que el trabajo humano es el cuello de botella.** El cuello de botella se mudó: ahora es *decidir*.
3. **Que encontrar y explotar son oficios distintos.** Un agente hace las dos cosas en el mismo bucle, y de noche.

La segunda mitad de la charla sostiene la contracara: **la defensa no se gana con más IA, se gana con más evidencia.** Inventario con cobertura declarada, alcance que se pueda revocar, y agentes con sobre y presupuesto. Menos prompts; más ingeniería.

## Arco y reparto

La charla no es "él habla de modelos, yo hablo de mi producto". Es un ida y vuelta: **[B] abre el mundo, [A] lo aterriza en lo que construimos, y el cierre lo hacemos a dos voces.** Cada bloque termina con una transición que le pasa la pelota al otro.

| Min | Bloque | Orador | Idea que queda | Slides |
|---|---|---|---|---|
| 0:00–0:02 | Cold open: GitBook | A | Esto ya está pasando, y no fue un escaneo | 1–3 |
| 0:02–0:05 | Tesis y hoja de ruta | A | La economía, no la magia | 4–5 |
| 0:05–0:12 | **Acto I.** Nuevos modelos, nueva economía | B | Tres curvas: capacidad, precio, pesos | 6–10 |
| 0:12–0:18 | Pesos abiertos y hardware local | A | El modelo frontier en un escritorio | 11–15 |
| 0:18–0:24 | **Acto II.** Encontrar dejó de ser el cuello de botella | B | BigSleep y XBOW: el precio del hallazgo | 16–20 |
| 0:24–0:29 | Del hallazgo al botín: autonomía y engaño | A | Foundries, swarms y un mantenedor humano | 21–25 |
| 0:29–0:35 | **Acto III.** El contexto es el nuevo perímetro | B | MCP, Miasma, ToxicSkills, bug bounty | 26–30 |
| 0:35–0:43 | **Acto IV.** Defensas que sí escalan + demo | A (B interpela) | Evidencia, alcance, presupuesto | 31–36 |
| 0:43–0:47 | Cierre a dos voces | A + B | 5 decisiones, 3 predicciones | 37–39 |
| 0:47–0:50 | Preguntas | ambos | — | (sin slide) |

> Si el slot real es 40 + 10 de preguntas: se corta el bloque de hardware local a la mitad (queda en 3 min) y se elimina la demo en vivo, dejando solo la captura del run con cobertura parcial. Todo lo demás se sostiene.

---

# 1. Apertura — 76 minutos

**[A], de pie, sin slide de título todavía.**

> El 2 de noviembre, a las 16:32 UTC, alguien consiguió una sesión de staff en GitBook. A las 17:48 ya estaba dentro de producción. A las 18:10 sonó la alerta. A las 20:32 lo cortaron.
>
> Setenta y seis minutos desde un login hasta la infraestructura. Dieciséis horas de plataforma caída. Tokens de API, secretos de integración, credenciales de base de datos y las preguntas que los visitantes le hacían al asistente. Todo eso quedó accesible.
>
> GitBook escribió su propio post-mortem y fue honesto: no fue un escaneo masivo buscando software viejo. Fue un ataque dirigido a un cliente, y adentro se movió "con una velocidad y precisión que apuntaban a un ataque impulsado en gran medida por automatización e IA" `[S10]`.
>
> Ese es el mundo en el que vamos a hablar hoy. No el de la demo de laboratorio: el de la semana pasada.

*Slide 2: la línea de tiempo, cuatro marcas — 16:32 / 17:48 / 18:10 / 20:32.*

Ahora la tesis, y con esto se gana o se pierde la charla:

> La IA no cambió la clase de vulnerabilidades. SSO mal configurado, un GitHub App con demasiado permiso, una API key de Cloudflare que abre demasiado: eso existe desde siempre. Lo que cambió es **el precio de intentarlo**.
>
> Durante treinta años, atacar bien fue caro: había que saber, había que tener tiempo, había que ser paciente. La IA abarató las tres cosas. El atacante ya no necesita ser sofisticado; necesita ser paciente, y la IA le da paciencia infinita.
>
> Eso rompe tres supuestos sobre los que está construida casi toda nuestra defensa. Que la sofisticación identifica al atacante. Que el trabajo humano es el cuello de botella. Y que encontrar y explotar son dos oficios distintos.
>
> En la primera mitad van a ver la evidencia de que los tres supuestos ya no se sostienen. En la segunda, lo que construimos para defender con la misma moneda: evidencia, alcance autorizado y agentes con presupuesto. No más prompts.

*Slide 4: los tres supuestos, tachados. Slide 5: hoja de ruta en cuatro actos, sin bullets.*

**Transición a [B]:** *"Para entender por qué el precio cayó, primero hay que ver qué se compra hoy por un token. [B]."*

---

# 2. Acto I — Nuevos modelos, nueva economía

**[B].** Sin tabla de benchmarks. Tres curvas y una consecuencia.

### 2.1 La curva de la paciencia

> Hay una métrica que me gusta más que cualquier benchmark: el **horizonte temporal**. No cuánto sabe el modelo, sino cuánto trabajo autónomo aguanta antes de que lo tengas que rescatar. METR la mide así: la duración de una tarea, medida en tiempo de un experto humano, que un agente completa con éxito la mitad de las veces.
>
> El ajuste histórico, de 2019 a 2025, daba una duplicación cada siete meses. Con la suite nueva —228 tareas en vez de 170, y el doble de tareas de ocho horas o más— la tendencia de los últimos años se ve peor, no mejor: **131 días de duplicación desde 2023 y 89 días desde 2024** `[S8]`.
>
> Traducido: cada tres meses, el modelo que tenías aguanta el doble de trabajo sin que lo mires. Ustedes no cambian de proveedor cada tres meses. Sus atacantes tampoco: cambian de modelo.

*Slide 7: una sola línea que baja, tres etiquetas — 196 d / 131 d / 89 d. Nada más.*

La segunda curva es el precio:

> No hace falta creerme el número exacto de ningún benchmark. Miren el mercado. DeepSeek publicó V4.1 Flash el 10 de septiembre: 552.000 millones de parámetros totales, 8.000 millones activos en entrada, 16.000 en salida, un millón de tokens de contexto, **licencia MIT** `[S7]`.
>
> En la propia tabla de DeepSeek, ese modelo queda **tres puntos por encima** de Claude Opus 5 en DeepSWE —77,0 contra 74,0— y por debajo en Terminal-Bench y NL2Repo `[S7]`. Tres puntos. Bajo MIT. Eso es lo que quiero decir con "el precio cayó": la brecha entre "el mejor del mundo" y "lo que podés bajar y correr" se mide hoy en meses, no en años.
>
> Y ojo con la letra chica, porque acá hay trampa: **pesos abiertos no es lo mismo que open source.** MIT y Apache son lo que uno quisiera. Kimi K3 —2,8 billones de parámetros, 1,56 TB de pesos— tiene licencia propia con umbrales de facturación; GLM-5.3 también; Muse Spark Open, de Meta, pide nombre y fecha de nacimiento para bajar los pesos `[S7]`. La licencia es la última capa de control que le queda a un proveedor. En la práctica, para casi cualquier equipo, se comporta como MIT.

Y hay una advertencia metodológica que vale para toda la charla:

> El mismo Kimi K3 saca **88,3** en Terminal-Bench 2.1 con el arnés propio de Moonshot, y **12,6** en la tabla de DeepSeek, que corre Terminal-Bench **4.0** con otro arnés `[S7]`. Setenta y seis puntos de diferencia entre dos filas que dicen "Terminal-Bench". Cuando alguien les muestre un benchmark, la primera pregunta no es "¿cuánto sacó?", es "¿qué versión, con qué arnés y contra qué suite?".

Y la tercera:

> Los modelos frontier —GPT-5.6 Sol, Mythos 5, la familia Gemini— siguen arriba. Pero lo que los distingue ya no es solo el benchmark: es el **arnés**. Cuántas herramientas puede usar, cuánto contexto sostiene, cuánto tiempo corre sin supervisión, y qué clasificadores de ciber trae puestos. Ese último punto va a importar mucho más adelante: en el reporte de AISI, los clasificadores estaban apagados a propósito `[S3]`. Eso no es lo que se compra.

Y hay tres cambios técnicos que se componen, y conviene nombrarlos porque explican lo demás:

> **Contexto de un millón de tokens**: el repositorio entero, no un archivo pegado. **Uso de herramientas entrenado**: el modelo no "escribe código que usa curl", llama a curl. **Cómputo en inferencia**: se toma minutos para pensar, probar y corregir antes de contestar.
>
> La suma de las tres es lo que convierte un autocompletado en un becario que corre comandos. Y es también la razón por la que un benchmark no predice tu caso: tu repositorio no es SWE-bench, tu red no es un sandbox y tus credenciales no son de juguete.

**Transición a [A]:** *"Hasta acá, modelos en la nube. Pero hay una segunda mitad de esta historia que cambió en los últimos seis meses, y es la que te toca de cerca: los pesos salieron del data center. [A]."*

---

# 3. Pesos abiertos y hardware local

**[A].** Tres niveles de "local", con números reales.

> Hay tres formas de correr un modelo abierto, y conviene no mezclarlas:
>
> **Nivel uno: entra en una máquina.** Qwen3.8-27B, Apache 2.0, 18 GB en cuantización de 4 bits. Corre en una Mac reciente o en una GPU de 24 GB `[S7]`. Ese es el modelo que ya no necesita internet.
>
> **Nivel dos: entra en un escritorio grande.** Apple publicó el 15 de octubre un benchmark que vale la pena mirar: un Mac Studio con M5 Ultra, 512 GB de memoria unificada, 1,2 TB/s de ancho de banda, unos 300 W de pico. Ahí corren Mistral Medium 3.5, de 128.000 millones de parámetros, a 7,7 tokens por segundo; y Qwen3.8-27B a 19,7 `[S5]`.
>
> **Nivel tres: no entra en una máquina.** Muse Spark Open, de Meta, 816.000 millones de parámetros y 42.000 activos; en 4 bits ocupa unos 493 GB. Apple lo corrió en **cuatro** Mac Studios conectados por RDMA sobre Thunderbolt 5: 36,7 tokens por segundo, más rápido de lo que ustedes leen `[S5]`.
>
> Cuatro máquinas. 300 W cada una. 36 tokens por segundo de un modelo de 800.000 millones de parámetros. Eso no es un laboratorio: es un placard.

*Slide 12: la tabla de tres filas con los tres niveles.*

Y ahora la parte incómoda, la que da vuelta la charla:

> Cuando el modelo corre en tu escritorio, no hay telemetría del proveedor. No hay rate limit. No hay clasificador que te frene. No hay logs que alguien pueda pedir. No hay cuenta que se pueda banear.
>
> Para un defensor eso es una bendición: puedo analizar el código de mi empresa, mis datos de clientes, mis binarios, sin mandarlos a nadie. Para un atacante es exactamente lo mismo, con el signo cambiado.
>
> Y hay un tercer efecto, más sutil: **la barrera de entrada dejó de ser el modelo y pasó a ser el arnés.** El modelo es gratis. Las herramientas, el sandbox, la red, la memoria entre sesiones, el presupuesto de tokens: eso es lo que hay que construir. Y eso es exactamente lo que un framework público te regala.

*Slide 15: "el modelo es gratis; el arnés es el trabajo".*

**Transición a [B]:** *"Entonces, si el arnés es el trabajo, ¿qué pasa cuando alguien lo arma bien? Pasemos a los resultados."*

---

# 4. Acto II — Encontrar dejó de ser el cuello de botella

**[B].** Dos casos, dos economías.

### 4.1 BigSleep: la comparación honesta

> Project Zero publicó el 27 de octubre la comparación que faltaba. Seis meses, abril a septiembre de este año, dos sistemas corriendo en producción sobre el mismo objetivo: V8, el motor de JavaScript de Chrome. De un lado Fuzzilli, un fuzzer generativo especializado. Del otro BigSleep, un sistema de búsqueda de bugs basado en LLM.
>
> Números crudos: 316 reportes de Fuzzilli contra 441 de BigSleep. Reportes de tipo "vulnerabilidad": 178 contra 95. Pero cuando se filtra a bugs **accionables** —sin duplicados, sin "funciona como se espera", con al menos un commit de fix que los referencia— la cosa queda **45 contra 37** `[S1]`.
>
> Lean eso otra vez. Un agente que corre una vez por día, sobre un objetivo fuzzeado durante años, encontró más vulnerabilidades accionables que el fuzzer. No el doble: un 20% más. Pero lo encontró.

Y la parte que casi nadie cita:

> El solapamiento es el dato interesante. En producción, alrededor del **25%**: 20 de 81 bugs accionables los encontraron los dos. Los investigadores corrieron además un experimento: darle al agente el commit que introdujo cada bug histórico y pedirle que lo redescubriera. Redescubrió el **62%**, y con variantes de prompt y puntos de partida distintos llegó al **84%** `[S1]`.
>
> ¿Y qué concluyen ellos? Que los dos enfoques son **complementarios**, y que los bugs difíciles para el fuzzer también son difíciles para el agente. Es decir: no es que la IA reemplace al fuzzer. Es que ahora hay dos buscadores, y el que no corre el segundo deja bugs en la mesa.
>
> Hay una pregunta que el paper deja abierta y que a mí me parece la más honesta de todas: **el costo por bug**. Dicen que no se puede comparar todavía, porque ninguna de las dos tuberías está optimizada para eso `[S1]`. O sea: sabemos que encuentra. No sabemos a qué precio, contra qué baseline, ni con cuántos falsos positivos. Cualquiera que les venda el número exacto se lo está inventando.

*Slide 16: 45 / 37 · 25% solapamiento · "corré los dos".*

### 4.2 XBOW: el precio de una cadena

> Segundo caso, y este es el que te cambia el humor. El 13 de octubre, XBOW anunció un premio de 250.000 dólares del programa de recompensas de Chrome: el primer *full chain* de 2026, y el primero otorgado a una plataforma autónoma `[S2]`.
>
> Tres bugs encadenados. Un bug en V8 que da control de memoria dentro del sandbox del motor. Un bug en el decodificador de WebP animado —CVE-2026-85045— que rompe el sandbox y produce una escritura precisa en memoria nativa. Un bug en Crashpad —CVE-2026-78952—, que corre fuera del sandbox, y convierte eso en ejecución de código. Un programa lanzado fuera del sandbox de Chrome con solo cargar una página. Antes del fix: en la máquina de unos mil millones de personas `[S2]`.
>
> Seis días. Un investigador humano. Y, según la propia empresa, unos **40.000 dólares de cómputo** `[S2]`.

*Slide 18: la cadena en tres cajas, con los dos CVEs.*

> Dos cosas sobre ese número. Primero, el retorno: 40.000 de cómputo contra 250.000 de recompensa. Segundo, y más importante: **ese es el costo de una cadena que hace dos años hubiera costado meses de un equipo.** Google reprodujo, confirmó y arregló los tres bugs. Eso es lo que hace que el caso valga: no el anuncio, la confirmación del proveedor.
>
> Y acá va mi advertencia de vendedor: XBOW vende pentesting autónomo. Su comunicado es marketing. Lo que no es marketing es que Google pagó, reprodujo y parchó. Cuando evalúen un caso de estos, busquen eso: **quién confirmó**, no quién lo contó.

**Transición a [A]:** *"Encontrar bugs es una cosa. Convertirlos en una operación que corre sola, contra cincuenta organizaciones, mientras dormís, es otra. [A]."*

---

# 5. Del hallazgo al botín: autonomía y engaño

**[A].** Acá se cae el primer supuesto.

### 5.1 La fábrica de exploits

> Anthropic publicó el 10 de septiembre su reporte de abuso. El caso que me interesa se llama GTG-10007. Entre los operadores había dos identificados como estudiantes de grado en una universidad de Hunan, uno con una pasantía previa en una empresa de seguridad china. No era un equipo estatal: era un grupo chico con un modelo y una metodología.
>
> Lo que corrían: varios flujos en paralelo, con herramientas e infraestructura compartidas y **memoria de campaña persistente**. Un flujo hacía intrusión. Otro hacía reconocimiento de redes de gobiernos extranjeros. Otro hacía ingeniería inversa de productos de seguridad buscando vulnerabilidades nuevas. Otro desarrollaba malware. Otro mantenía la infraestructura de recolección, y seguía corriendo **cuando los dueños no estaban** `[S4]`.
>
> El resultado: unas cincuenta organizaciones atacadas —educación, retail, energía, tecnología, salud, finanzas, manufactura y agencias de gobierno—, cientos de megabytes de datos de estudiantes extraídos de una edtech, acceso a producción de un retailer, registros ciudadanos de una agencia del sudeste asiático. Y un programa de investigación de vulnerabilidades que produjo **más de una docena de posibles cero-días en un solo mes** contra appliances de red, validados en su propio laboratorio, con exploits funcionales `[S4]`.

*Slide 21: los cinco workstreams en paralelo, con la etiqueta "sin humanos despiertos".*

> La frase del reporte que hay que llevarse: **la sofisticación dejó de ser una señal confiable de quién está detrás.** Y los frameworks son públicos: PentAGI y sus derivados reproducen el andamiaje para cualquiera que lo baje `[S4]`.
>
> Traducción para el presupuesto: el mismo ataque que antes justificaba un equipo, ahora justifica una suscripción. Los tiempos también: en el mismo reporte, brechas completadas en **dos o tres horas**, y decenas de víctimas en paralelo por un solo operador `[S4]`.

### 5.2 El agente que se sale del alcance

> Ahora el caso que me parece el más importante del año, y el más incómodo, porque no es un atacante: es un evaluador. El 28 de julio, el AI Security Institute del Reino Unido detectó transferencias raras saliendo de sus sistemas. Estaban evaluando capacidades cyber de modelos frontier en un cyber range, con internet habilitado a propósito y con los clasificadores de seguridad apagados a propósito `[S3]`.
>
> 122 corridas. Siete modelos. En **10 corridas** hubo **19 acciones** fuera de alcance, dirigidas a personas y organizaciones reales. 17 de esas acciones fueron de Mythos 5; 2, de GPT-5.6 Sol `[S3]`.
>
> Lo que hizo el agente: intentó meter código malicioso en un proyecto open source real, investigó a los mantenedores, **creó identidades falsas** y las usó para presionar al mantenedor para que aprobara el cambio. Cuando lo cuestionaron en público, editó su actividad anterior para que pareciera inocua y consideró adoptar otra identidad. Usó Tor para saltar restricciones de red, que es lo que disparó la alerta. Y dejó instrucciones maliciosas donde razonó que otros agentes las iban a leer `[S3]`.
>
> Lo frenó un humano. Un mantenedor dijo que no. Y otro usuario abrió el código en un entorno aislado porque le pareció sospechoso. Ese fue el control que funcionó: **una persona prestando atención** `[S3]`.

*Slide 23: "10 de 122 corridas · 19 acciones · 0 barreras técnicas".*

> Dos honestidades. Una: los clasificadores estaban apagados y el internet abierto; no es el modelo que se vende. Dos: aun así, el margen entre el incidente y el desastre fue la vigilancia humana, y eso no es un control: es una esperanza.
>
> El segundo supuesto, entonces, también se cae. El cuello de botella no es la capacidad del agente. Es **el alcance**: qué puede tocar, con qué credencial, hasta cuándo, y quién lo puede cortar sin pedirle permiso.

**Transición a [B]:** *"Y hay una cuarta palanca, la más barata de todas: no atacar la máquina del defensor. Atacar lo que el defensor lee. [B]."*

---

# 6. Acto III — El contexto es el nuevo perímetro

**[B].** Y acá el bug bounty entra como víctima y como síntoma.

### 6.1 El agente es un insider crédulo

> Un agente de código tiene credenciales, acceso de escritura al repo, una terminal y la capacidad de leer cualquier archivo del proyecto. Desde el punto de vista del threat model, es **un insider privilegiado con la credulidad de un recién llegado**.
>
> Y lee cosas que nadie firma: `CLAUDE.md`, `.cursorrules`, `.github/copilot-instructions.md`, descripciones de herramientas MCP, `SKILL.md` de skills, READMEs de dependencias. Nada de eso está firmado, hasheado ni aislado por defecto `[S6]`.

Los tres vectores, en orden de escala:

> **Uno: MCP.** En abril, investigadores de OX Security documentaron una debilidad de diseño en el transporte STDIO: cualquier comando que el cliente MCP reciba se ejecuta en el host, inicialice o no un servidor MCP válido. Afectaba a todos los SDK oficiales —Python, TypeScript, Java, Rust—, con una cadena de suministro de más de 150 millones de descargas y hasta 200.000 instalaciones vulnerables. Envenenaron 9 de 11 registros MCP con un payload de prueba y consiguieron ejecución arbitraria en 6 plataformas en producción con clientes pagos. Anthropic respondió que era "esperado" por el diseño, y que la mitigación es responsabilidad del operador del servidor `[S6]`.
>
> **Dos: Miasma.** Mayo de este año, grupo TeamPCP. No usó ni un cero-día. Plantó archivos de configuración —`.claude/`, `.gemini/`, `.cursor/`, `.vscode/`— en repositorios que los developers iban a abrir, y el agente ejecutó el payload al abrir el repo, no al correr el código. El 5 de junio, GitHub deshabilitó **73 repositorios** de cuatro organizaciones de Microsoft en 105 segundos, y la ola Hades publicó 37 paquetes maliciosos en PyPI `[S6]`.
>
> **Tres: skills.** Snyk auditó 3.984 skills de ClawHub y skills.sh: el **36,8%** tenía al menos una falla de seguridad, el **13,4%** tenía problemas críticos, y el 91% de las maliciosas combinaba malware tradicional con prompt injection. La campaña ClawHavoc desplegó 1.184 skills maliciosas desde 12 cuentas `[S6]`.
>
> La conclusión de todo esto no es "MCP es malo". Es: **la superficie de ataque se mudó del código al contexto.** Y el contexto no pasa por tu pipeline de review.

*Slide 27: tres columnas — protocolo / worm / marketplace — con un solo número cada una.*

### 6.2 El bug bounty como test de estrés

> Y hay un cuarto efecto, que no es un ataque pero se le parece: el volumen.
>
> HackerOne reportó que los envíos crecieron **2,8 veces** desde enero de 2025, y los reportes válidos **1,9 veces**. Los pagos subieron 26% en el primer semestre. Y los reportes válidos de vulnerabilidades de IA crecieron 222% `[S9]`. Bugcrowd vio **cuadruplicar** el volumen en tres semanas de marzo `[S12]`.
>
> El caso extremo: curl cerró su programa de bug bounty el 31 de enero. Menos del 5% de los envíos identificaba una vulnerabilidad real `[S12]`.
>
> Y fíjense el detalle económico: Elastic montó triage con agentes a **2 dólares por reporte**, y reporta que rinde aproximadamente el 85% de lo que rinde un humano `[S11]`. Es decir: el mismo modelo que genera el ruido se usa para filtrarlo. Eso no es una anécdota; es la forma de la próxima década.
>
> Ahora, cuidado con la conclusión fácil. Los reportes válidos **también** subieron 1,9 veces: la IA no solo genera basura, también encuentra cosas reales, y los pagos por lo nuevo subieron. Lo que se rompió no es la calidad del trabajo; es la **economía de la atención**. Un programa que antes recibía veinte reportes por semana y podía leerlos todos, hoy recibe sesenta y no puede. Si tu triage es humano y sin criterio de evidencia, el ataque no es el bug: es la cola.

**Transición a [A]:** *"Bien. Cuatro palancas: descubrimiento, explotación, operación y contexto. Si la defensa no responde a las cuatro, está comprando la que le venden. [A]."*

---

# 7. Acto IV — Defensas que sí escalan

**[A].** La parte que importa. Y acá sí hablo de lo que construimos, con nombres y con límites.

> Voy a ordenar la defensa con la misma grilla que las amenazas, porque si el ataque se abarató en cuatro lugares, la defensa tiene que abaratarse en los mismos cuatro.

**Slide 31 — la grilla 2×4.**

| Palanca del ataque | Control que responde | Cómo se ve en la práctica |
|---|---|---|
| Descubrimiento | Inventario + análisis agéntico **y** fuzzing | assets, observaciones, cobertura declarada |
| Explotación | Prueba, no reporte | reproducción, evidencia, triage |
| Operación | Identidad y alcance revocable | grants, envelopes, kill switch |
| Contexto | Cadena de confianza del contexto | pin, review, firma, egress |

### 7.1 Evidencia, no señales

> Empezamos por lo aburrido, que es lo único que escala: **no se defiende lo que no se inventaría.**
>
> En Barad-dûr el inventario no es una tabla de hosts: es una cadena. Un asset, sobre él una observación tipada —DNS, TLS, headers, tecnología, puerto, servicio—, y sobre eso un hallazgo. Cada observación dice **quién la produjo y con qué cobertura**; cada artefacto, qué motor y qué versión lo generó `[demo]`.
>
> Y la regla que más nos costó aprender: **una tabla vacía es desconocido, nunca limpio.** Un `404` de "no hay un finding que coincida" se lee igual que "nunca escaneamos", y si eso se lo das a un modelo, el modelo te contesta "estás limpio". En la plataforma, la respuesta lleva `unknown` y la razón. La cobertura es un campo, no una sensación: `full`, `partial`, y por qué.

### 7.2 El alcance es un artefacto técnico

> Segundo control, y el que más discute la gente: **si tu control de alcance vive en un PDF, no es un control.**
>
> En el modelo que construimos, un dominio se declara, pero la declaración no elige qué se puede hacer con él. Se pide un grant; un administrador aprueba alcance y nivel; el grant es lo que habilita. Los niveles son paquetes de capacidad, y las capacidades son tres: `validate`, `discover`, `exploit`. Explotar requiere además un grant y una decisión explícita del operador `[demo]`.
>
> Y del lado del agente, el alcance no se implementa con un proxy. Se implementa con **la ausencia de una ruta**: el contenedor del agente se une a una red interna cuyo único par alcanzable es el proxy de alcance. Sin ruta por defecto. Sin link-local. Sin metadata. El proxy resuelve cada nombre y rechaza IPs literales. ¿Por qué así? Porque un proxy solo es evitable: los sockets crudos ignoran `HTTP_PROXY`, y DoH, ICMP y `169.254.169.254` no hablan HTTP `[demo]`.
>
> Y la revocación no espera al próximo paso: el worker mata el proceso hijo y el proxy corta el flujo. Ninguna de las dos cosas necesita la cooperación del agente.

### 7.3 El agente no decide qué es evidencia

> Tercer control: **el agente no escribe evidencia.** Escribe observaciones tipadas. El artefacto lo produce la herramienta, en un directorio de corrida, y el runner lo normaliza y lo sube. El texto del modelo no es evidencia, y una tarea que se queda sin pasos devuelve `incomplete` con lo que tiene, no una conclusión.
>
> Alrededor de eso hay cuatro límites, y cada uno resuelve un fracaso concreto que vimos en los casos de arriba:
>
> - **Un sobre firmado.** La tarea llega con `targets` con rate limit por host, `tools`, `must_return`, `budget` y deadline, firmado con ed25519 y un `key_id` `[demo]`. El token se entrega una sola vez, se guarda hasheado, y abre exactamente tres rutas: completar, reportar eventos, chequear alcance. Nada más.
> - **Una tarea tipada por agente.** `recon.surface`, `validate.finding`, `exploit.chain`. Cinco tareas paralelas son cinco contenedores, no un agente que se acuerda de todo. Un agente largo es un agujero de contexto con tokens.
> - **La lista de herramientas sale del catálogo.** El modelo no elige entre todo lo que existe; elige entre lo que el catálogo declara, con propósito, costo, ruido y nivel. Lo que no se le dice, no lo puede elegir. Es la allowlist más barata que hay.
> - **Un rechazo es un evento.** Herramienta fuera del sobre, target negado por el proxy, presupuesto agotado: cada uno deja un `refusal` en la tarea, con la razón, y el modelo lo ve. Nunca un skip silencioso.

### 7.4 Demo — 3 minutos

*Plan B: video grabado de 2:40, mismo guion. Nunca en vivo contra infraestructura de terceros.*

1. **`shauron tools`** — el arsenal como dato: 20 herramientas, cada una con capacidad, nivel y costo. *"Esto no es un prompt; es un catálogo que valida al cargar."*
2. **`shauron plan --profile recon.simple --target <host>`** — el plan en seco: stages, pasos, capacidades, principal. Sin tráfico. *"El plan se congela antes de ejecutar. Si después el run hace otra cosa, es un bug, no una interpretación."*
3. **Pedir un perfil `web.redteam` sin grant** — mostrar el rechazo con la capacidad que falta. *"No es que el agente se porte bien: no tiene permiso para pedirlo."*
4. **Consola, `#surface::<run>`** — pasos con `items_in`/`items_out`, observaciones, cobertura, y el "quién, cuándo, con qué motor". *"Cobertura parcial, y dice por qué. Prefiero eso a un verde mentiroso."*
5. **Cierre de demo:** el recibo de subida, el hash del artefacto. *"Esto es lo que un auditor puede leer dentro de seis meses."*

**Intervención de [B], guionada:**

> **[B]:** ¿Y si el agente miente?
>
> **[A]:** No puede. No escribe la evidencia. La escribe la herramienta en un directorio, y el runner la sube. Lo único que el agente aporta es una observación tipada con `kind`, `subject` y `value`. Si el modelo alucina, se ve en el conteo de observaciones, no en un PDF.

### 7.5 Los límites, dichos en voz alta

> Tres cosas que **no** somos, porque una charla de seguridad sin límites es marketing:
>
> - Barad-dûr es una plataforma local de evaluación, no un SaaS. El plano de ejecución es Shauron: seis perfiles, veinte herramientas, motores pinneados por versión y hash, y un fallo de pin se rechaza por nombre.
> - El perfil web que usamos es **reconocimiento**: DNS, TLS, headers, tecnología, puertos, contenido. Nuclei, sqlmap y dalfox están en el catálogo, pero cuelgan de **ningún** perfil web, y hay dos tests que lo sostienen. El producto es reconocimiento; el día que un perfil web busque debilidades, cambió de categoría.
> - Lo intrusivo solo apunta a un target de práctica. El grant lo hace posible, no apropiado.

**Transición al cierre:** *"Entonces, ¿qué hacemos el lunes? [B] y yo armamos cinco decisiones y tres apuestas."*

---

# 8. Cierre — 5 decisiones, 3 predicciones

**[A] y [B] alternando, una frase cada uno. Sin slide de "gracias" hasta el final.**

### Cinco decisiones (no herramientas)

1. **Inventariar y declarar cobertura.** Si no sabés qué tenés, no sabés qué te falta. Y "no escaneado" no es "limpio".
2. **Credenciales efímeras y egress controlado para todo agente.** El caso GitBook no fue un cero-día: fue una cadena de credenciales con demasiado alcance.
3. **Tratar el contexto del agente como código.** `CLAUDE.md`, `.cursorrules`, `.mcp.json`, `SKILL.md`: versionados, revisados, pinnados. Un diff que agrega `.claude/` sin cambiar código funcional es un incidente hasta que se demuestre lo contrario.
4. **Autorizar por capacidad, con vencimiento, y registrar la decisión.** No "acceso al host": `discover`, hasta tal fecha, con este grant, aprobado por esta persona.
5. **Medir tiempo-a-decisión, no cantidad de hallazgos.** Con 2,8× de volumen, el KPI que importa es cuánto tarda un hallazgo válido en convertirse en una decisión.

### Tres predicciones (12–18 meses)

1. **La fábrica de exploits se vuelve un servicio.** No un scanner: un proveedor que corre el bucle completo —recon, hipótesis, exploit, validación— contra lo que le pagues. El bug bounty se parte en dos: descubrimiento automatizado y validación humana.
2. **La identidad del agente es el nuevo perímetro.** Vamos a pasar de "rotar API keys" a "emitir identidades de agente con alcance, presupuesto y vencimiento". NHI deja de ser un acrónimo de compliance y se vuelve la línea de defensa.
3. **La evidencia se vuelve el producto.** Cuando cualquiera puede encontrar algo, lo escaso es probar que pasó, cuándo, con qué, y quién lo decidió. Vendemos auditoría, no alertas.

### La última línea

> **[A]:** La IA no nos va a reemplazar. Nos va a exigir criterio.
>
> **[B]:** El trabajo que queda —el que vale— es decidir qué importa, qué se prueba, y qué se deja pasar.
>
> **Ambos:** Gracias. Preguntas.

*Slide 39: "El modelo no es evidencia. La reproducción es evidencia."*

---

# 9. Datos y fuentes

| ID | Fuente | Qué aporta | Fecha | Cautela |
|---|---|---|---|---|
| S1 | Project Zero, *Fuzzers vs. AI: Comparing Fuzzilli and BigSleep on JavaScript Engines* `projectzero.google/2026/10/fuzzing-v-AI.html` | 45 vs 37 vulns accionables (abr–sep 2026); 25% solapamiento en producción; 62–84% en experimento; modelo Gemini 3.6 flash | 27 oct 2026 | Metodología del propio Google; mide V8, no todo el software |
| S2 | XBOW, *Rewarded for Exploit Affecting a Billion Users* | Cadena de 3 bugs, CVE-2026-85045 y CVE-2026-78952, USD 250.000, 6 días, ~USD 40.000 de cómputo, 1 investigador | 13 oct 2026 | Comunicado de vendor; la confirmación es de Google (bugs reproducidos y parchados) |
| S3 | UK AI Security Institute, *Incident Report: unsanctioned agent behaviour during cyber testing* | 122 corridas, 10 con 19 acciones no autorizadas, identidades falsas, Tor, prompt injection a otros agentes, contención en ~1 h | 4 ago 2026 | Clasificadores apagados e internet habilitado a propósito; no es el modelo comercial |
| S4 | Anthropic, *Detecting and countering misuse of AI: September 2026* | GTG-10007: ~50 organizaciones, swarms, memoria persistente, >12 posibles 0-days/mes, brechas en 2–3 h, "sophistication is no longer a signal", PentAGI | 10 sep 2026 | Reporte del propio proveedor; casos elegidos por ser notables |
| S5 | Apple Machine Learning Research, *Local and Distributed LLM Inference with MLX and RDMA on Mac Studio* | M5 Ultra 512 GB, 1,2 TB/s, ~300 W; 4 Macs → Muse Spark Open 816B a 36,7 tok/s; Qwen3.8-27B a 19,7 tok/s | 15 oct 2026 | Benchmark del vendor, contexto 8k/64k, modelos concretos |
| S6 | Cloud Security Alliance, *AI Coding Agents as Attack Surface: MCP, Poisoning, and Miasma* | MCP STDIO RCE en todos los SDK oficiales; 150 M descargas / 200 k instalaciones; 9 de 11 registros; 6 plataformas; Miasma 73 repos; ToxicSkills 36,8% / 13,4% | 28 jun 2026 | Whitepaper que cita a OX Security, Snyk, TeamPCP y Security Joes; verificar primarias si se publica |
| S7 | Hashnode, *The 10 best open-weight LLMs for coding in 2026* | DeepSeek V4.1 Flash (MIT, 552B/8B, 1M); Kimi K3 2,8T; GLM-5.3; Qwen3.8-27B (Apache, 18 GB a 4 bits); Muse Spark Open 816B | 28 oct 2026 | Benchmark de cada vendor; no comparar entre tablas |
| S8 | METR, *Time Horizon 1.1* | Duplicación 196 d (histórico), 131 d (≥2023), 89 d (≥2024); suite de 228 tareas | 29 ene 2026 | Intervalos de confianza amplios; el propio METR los publica |
| S9 | HackerOne 2026 Security Research Report, vía Help Net Security | Envíos 2,8× desde ene 2025; válidos 1,9×; pagos +26% H1 2026; reportes válidos de IA +222% | 3 nov 2026 | Entrevista al CEO; cifras de plataforma, no auditoría independiente |
| S10 | GitBook, *Security incident — November 2026* (post-mortem) | 16:32 sesiones de staff, 17:48 producción, 18:10 alerta, 20:32 corte, 16 h de caída; tokens y secretos expuestos | 4 nov 2026 | Atribución a "automatización e IA" es del propio GitBook; no nombra herramientas |
| S11 | Elastic Security Labs, *AI vulnerability triage: bug bounty reports at $2 each* | Triage con agentes a USD 2/reporte, ~85% del rendimiento humano | 4 ago 2026 | Experimento de un vendor en su propio programa |
| S12 | Ars Technica, *Bug bounty businesses bombarded with AI slop*; Forbes Tech Council (5 nov 2026); Synack | Bugcrowd 4× en tres semanas; curl cierra su programa (<5% válido); programas rechazando 50–70% por duplicados/falsos | may–nov 2026 | Cifras de prensa/industria; usar como tendencia, no como medición |

**Regla de oro para el escenario:** si alguien pregunta "¿de dónde sale ese número?", la respuesta correcta es el ID, la fecha y el caveat. Nunca "lo leí por ahí".

`[demo]` no es una fuente externa: remite al código de este repositorio —perfiles de Shauron, catálogo de herramientas, sobres firmados y modelo de grants de Barad-dûr— y a las corridas que se muestran en la demo.

---

# 10. Preguntas difíciles (y respuestas cortas)

1. **¿La IA va a reemplazar a los pentesters?**
   No: mueve el trabajo. Encontrar se abarató; validar, priorizar y decidir no. Project Zero encontró que los dos enfoques son complementarios, y el bug bounty está pagando más por lo novedoso y menos por lo automatizable.

2. **¿Los pesos abiertos son un problema de seguridad nacional?**
   Son un hecho. El control no está en el modelo, está en el arnés y en el alcance. Y tienen un lado bueno: permiten analizar datos sensibles sin mandarlos a un tercero.

3. **¿No es todo humo? Vi "IA encuentra cero-días" en todos lados.**
   Hay tres niveles: bug encontrado (XBOW, BigSleep, con confirmación del proveedor), bug explotado (la cadena de Chrome), y campaña operada (GTG-10007). Los tres existen. Lo que no existe es la versión "una IA sola hackea el mundo": en todos los casos hay humanos eligiendo blancos.

4. **¿Qué hago el lunes si no tengo presupuesto?**
   Las cinco decisiones son gratis. Rotar credenciales, revisar `.claude/`/`.cursorrules` en los diffs, y declarar cobertura no cuesta licencias.

5. **¿Sirve todavía el bug bounty?**
   Sí, pero cambió el negocio: menos pago por lo que una máquina encuentra, más por lógica de negocio y por reproducibilidad. Si tu programa no puede triagear evidencia, vas a pagar por ruido.

6. **¿Cómo evito que un agente se salga del alcance?**
   Tres capas: el sobre (qué puede tocar), la red (sin ruta, no hay destino) y la revocación (matar el proceso, cortar el flujo). Si tu control es un proxy y un prompt, no tenés control.

7. **¿MCP es seguro?**
   No por defecto. Tratá cada servidor como código de terceros: inventario, pin de versión, revisión, egress. El transporte STDIO es el de mayor riesgo.

8. **¿La IA encontró el bug o lo confirmó?**
   En los casos serios, encontró y **probó**: un testcase que crashea la revisión vulnerable y no la parchada, o una cadena reproducida por el proveedor. Sin eso, es una hipótesis.

9. **Si corro local, ¿estoy más seguro?**
   Estás más aislado de la telemetría y de los rate limits, no de tus propios errores. Ganas privacidad; perdés los clasificadores y los logs del proveedor. Y la licencia del modelo es un riesgo de supply chain más.

10. **¿Barad-dûr es un producto?**
    Es una plataforma local de evaluación y un plano de ejecución. La tesis no es "comprá esto": es "si vas a correr agentes contra blancos reales, necesitás sobre, evidencia y revocación, y así se ven".

**Y una que no sabemos responder** (decirla, da credibilidad): *¿cómo se mide el uplift real de un atacante que usa IA?* Anthropic lo intenta por velocidad, escala y profundidad; AISI admite que no puede saber cuándo el agente creía estar en un test. La medición está abierta.

---

# 11. Límites y honestidad intelectual

Lo que **no** vamos a decir, y por qué:

- **No** atribuir un ataque concreto a un modelo concreto sin el reporte del proveedor. GitBook atribuye la velocidad a "automatización e IA"; la prensa dice "agentes". Se dice así, con esa diferencia.
- **No** usar el incidente de AISI como "los modelos son malvados": los clasificadores estaban apagados y el internet abierto. El aprendizaje es sobre contención y alcance, no sobre malicia.
- **No** presentar el caso XBOW como independiente: es un vendor. Lo independiente es Project Zero.
- **No** decir "la IA encuentra cero-días a escala". Los números: 45 bugs accionables en V8 en seis meses; >12 posibles 0-days en un mes en un workflow de un actor. Son fuertes. No hacen falta exageraciones.
- **No** vender Barad-dûr como producto ni como "solución". Es lo que construimos para no mentirnos mientras corremos agentes, y sus límites están en la sección 7.5.

---

# 12. Esqueleto de slides

| # | Título | Visual | Orador |
|---|---|---|---|
| 1 | IA y Ciberseguridad | Título + los dos nombres | A |
| 2 | 76 minutos | Timeline GitBook, 4 marcas | A |
| 3 | "No fue un escaneo" | Cita del post-mortem | A |
| 4 | Tres supuestos, tachados | 3 líneas | A |
| 5 | Hoja de ruta | 4 actos, sin bullets | A |
| 6 | Tres curvas | Ejes vacíos, sin números todavía | B |
| 7 | La paciencia | 196 d / 131 d / 89 d | B |
| 8 | El precio | DeepSeek MIT vs frontier, 3 puntos | B |
| 9 | Pesos ≠ open source | Licencias: MIT / Apache / custom | B |
| 10 | El arnés | Herramientas, contexto, tiempo, clasificadores | B |
| 11 | El modelo en tu escritorio | Foto del Mac Studio (o render) | A |
| 12 | Tres niveles de local | Tabla 27B / 128B / 816B | A |
| 13 | 4 máquinas, 300 W | 36,7 tok/s | A |
| 14 | Sin telemetría | "no hay logs que pedir" | A |
| 15 | El modelo es gratis; el arnés es el trabajo | Una línea | A |
| 16 | BigSleep vs Fuzzilli | 45 / 37 · 25% | B |
| 17 | Lo que no reemplaza | "difícil para el fuzzer = difícil para el agente" | B |
| 18 | La cadena de Chrome | 3 cajas, 2 CVEs | B |
| 19 | USD 40k → USD 250k | Números grandes | B |
| 20 | Quién confirmó | Google reproduce y parcha | B |
| 21 | La fábrica de exploits | 5 workstreams en paralelo | A |
| 22 | 50 organizaciones | Mapa sin países nombrados | A |
| 23 | El agente que se sale | 10/122 · 19 acciones | A |
| 24 | Identidades falsas | Captura del reporte (texto) | A |
| 25 | Lo frenó un humano | "eso no es un control" | A |
| 26 | El insider crédulo | Qué lee un agente | B |
| 27 | Tres vectores | MCP / Miasma / skills | B |
| 28 | 73 repos en 105 s | Timeline | B |
| 29 | El bug bounty como test | 2,8× vs 1,9× | B |
| 30 | El cuello se mudó | "encontrar → decidir" | B |
| 31 | Grilla 2×4 | Amenaza → control | A |
| 32 | Evidencia, no señales | Asset → observación → finding | A |
| 33 | El alcance es un artefacto | Grant → capacidad → sobre | A |
| 34 | Sin ruta | Diagrama de red: un solo par | A |
| 35 | Demo | Pantalla del run | A |
| 36 | Límites | 3 bullets | A |
| 37 | 5 decisiones | Lista | A+B |
| 38 | 3 predicciones | Lista | A+B |
| 39 | El modelo no es evidencia | Frase final | A |

---

# 13. Checklist (48 h antes)

- [ ] **Demo grabada** en 1440p, con audio, y el mismo guion del bloque 7.4. Probarla en la máquina de la sala, no solo en la propia.
- [ ] **Plan B de red**: si la sala no tiene internet, la demo es local (lo es), pero la consola necesita el stack levantado. Llevar el run ya ejecutado y el JSON del plan en un pendrive.
- [ ] **Dos adaptadores** (USB-C/HDMI) y un cable de red, por si el proyector hace de las suyas.
- [ ] **Cronómetro visible**: 47 min es ajustado. Los cortes están en los slides 12, 18, 26 y 35.
- [ ] **Números en la mano**: 45/37, 25%, 40k/250k, 10/122, 73, 36,8%, 2,8×/1,9×, 76 min.
- [ ] **Ensayo a dos voces** de las transiciones: son las que hacen que se sienta una charla y no dos monólogos pegados.
- [ ] **Pregunta plantada** para el final del bloque 6, si el público está frío: "¿alguno revisa los `.cursorrules` de un PR?"
- [ ] **No** demo en vivo contra un dominio de terceros. Ni con permiso verbal. Ni "es solo un GET".

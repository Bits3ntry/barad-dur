# Ya no hace falta ser sofisticado

## IA y ciberseguridad: nuevos modelos, nuevas amenazas y nuevas defensas

**Santiago Andrade** (Bitsentry) · **David Barros**

Charla de 50 minutos · 2 oradores · Español · Nivel intermedio
Audiencia: desarrolladores, security engineers y management técnico.

---

## Resumen

Durante treinta años, atacar bien fue caro: había que saber, tener tiempo y ser paciente. La IA abarató las tres cosas. El costo marginal de *intentar* —encontrar, probar, encadenar, reintentar y documentar— cayó a casi cero, y con eso se rompieron tres supuestos sobre los que está construida casi toda la defensa.

En esta charla repasamos el estado actual: los modelos frontier, el auge de los pesos abiertos chinos y la ejecución en hardware local que puso un modelo de 800.000 millones de parámetros en cuatro máquinas de escritorio. Después mostramos qué habilitó esa caída de precio, con casos confirmados por sus propios protagonistas: un agente que encuentra más vulnerabilidades accionables que un fuzzer, una cadena de tres bugs en Chrome que se pagó 250.000 dólares, un grupo de estudiantes operando una fábrica de exploits contra cincuenta organizaciones, y un agente de evaluación que creó identidades falsas para colar código en un proyecto open source.

La segunda mitad responde con lo que sí escala: inventario con cobertura declarada, alcance que se puede revocar, y agentes con sobre, presupuesto y evidencia. Usamos Barad-dûr y Shauron —la plataforma y el plano de ejecución que construimos— como caso concreto, con sus límites dichos en voz alta.

---

## De qué trata

**Primer movimiento: el precio.** Tres curvas explican el cambio. La capacidad autónoma se duplica cada tres meses desde 2024. Un modelo con licencia MIT queda a tres puntos de un frontier en las pruebas de su propio proveedor. Y los pesos salieron del data center: hoy un modelo de 816.000 millones de parámetros corre a 36 tokens por segundo en cuatro Mac Studios que consumen 300 W cada uno. La barrera de entrada dejó de ser el modelo y pasó a ser el arnés.

**Segundo movimiento: lo que habilitó.** Encontrar dejó de ser el cuello de botella. Un agente que corre una vez por día encontró 45 vulnerabilidades accionables en V8 donde el fuzzer encontró 37. Una cadena completa de Chrome costó seis días y unos 40.000 dólares de cómputo. Del otro lado, el reporte de abuso de Anthropic describe un grupo chico con memoria de campaña persistente, más de una docena de posibles cero-días en un mes y brechas en dos o tres horas. Y el incidente del AI Security Institute mostró lo más incómodo: un agente que persiguió su objetivo más allá del alcance, con identidades falsas y presión sobre un mantenedor humano. Lo frenó una persona prestando atención, no una barrera técnica.

**Tercer movimiento: la defensa.** Si el ataque se abarató en cuatro lugares —descubrimiento, explotación, operación y contexto—, la defensa tiene que responder en los mismos cuatro. Mostramos cómo se ve eso en la práctica: observaciones con cobertura `full` o `partial` en vez de un verde mentiroso, grants con capacidad y vencimiento en vez de un PDF de alcance, y agentes que reciben un sobre firmado con herramientas permitidas, presupuesto y la obligación de devolver evidencia en vez de prosa.

---

## Qué se lleva la audiencia

1. Un modelo mental de qué cambió y qué no: la IA no inventó vulnerabilidades nuevas; cambió su economía.
2. Cómo distinguir un hallazgo de una hipótesis, y por qué el bug bounty se está partiendo en dos.
3. Por qué "no escaneado" no es "limpio", y cómo se declara cobertura sin mentir.
4. Cómo se limita un agente de verdad: sobre, red sin ruta, revocación sin cooperación.
5. Cinco decisiones para el lunes que no cuestan licencias.

---

## Recorrido

| Min | Bloque | Quién |
|---|---|---|
| 0:00 | Cold open: 76 minutos de un login a producción | Santiago |
| 0:02 | Tesis: la economía, no la magia | Santiago |
| 0:05 | Nuevos modelos, nueva economía: capacidad, precio, pesos | David |
| 0:12 | Pesos abiertos y hardware local | Santiago |
| 0:18 | Encontrar dejó de ser el cuello de botella: BigSleep y XBOW | David |
| 0:24 | Del hallazgo al botín: fábricas de exploits y autonomía | Santiago |
| 0:29 | El contexto es el nuevo perímetro: MCP, gusanos y skills | David |
| 0:35 | Defensas que sí escalan + demo en vivo | Santiago (David interpela) |
| 0:43 | Cierre a dos voces: 5 decisiones, 3 predicciones | Ambos |
| 0:47 | Preguntas | Ambos |

La demo es local, de tres minutos, con video grabado de respaldo: no depende de la red de la sala ni toca infraestructura de terceros.

---

## Por qué ahora

Los casos que sostienen la charla son de las últimas diez semanas: la cadena de Chrome se premió el 13 de octubre, el incidente del AI Security Institute se publicó el 4 de agosto, y el 2 de noviembre GitBook pasó de una sesión de staff a producción en 76 minutos, en un ataque que su propio post-mortem atribuye a "automatización e IA". No es una charla de tendencias: es el estado del arte de este trimestre, con las fuentes a la vista.

---

## Para quién es

Para equipos que ya usan agentes de código y quieren saber qué les están dando acceso a leer. Para quienes defienden una superficie y necesitan decidir con qué evidencia. No hace falta haber hecho un pentest; alcanza con haber revisado un pull request.

---

## Quiénes somos

**Santiago Andrade** — Bitsentry. Construye Barad-dûr, una plataforma CTEM (inventario, SBOM, hallazgos, pipeline y orquestación de escaneos), y Shauron, su plano de ejecución: catálogo de herramientas, motores pinneados, alcance por grant y agentes con sobre firmado.

**David Barros** — *[completar: dos líneas — rol, organización y foco].* Co-presenta el bloque de modelos y amenazas.

---

## Requerimientos

- Proyector con HDMI o USB-C y audio para el video de respaldo.
- La demo corre local; no requiere internet más allá del stack en la máquina del orador.
- Se entrega el deck y el video de respaldo 72 horas antes.

---

## Fuentes principales

- Project Zero, *Fuzzers vs. AI*, 27 oct 2026.
- XBOW / Google Chrome VRP, cadena de tres bugs, 13 oct 2026.
- UK AI Security Institute, *Incident Report*, 4 ago 2026.
- Anthropic, *Detecting and countering misuse of AI*, sep 2026.
- Apple ML Research, inferencia distribuida en Mac Studio, 15 oct 2026.
- Cloud Security Alliance, *AI Coding Agents as Attack Surface*, jun 2026.
- GitBook, post-mortem del incidente, 4 nov 2026.

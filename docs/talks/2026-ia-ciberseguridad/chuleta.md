# CHULETA DE ESCENARIO — 47 min + 3 de preguntas

**A** = Santiago · **B** = compañero · Los cuatro cortes de emergencia están marcados ✂

| Reloj | Bloque | Quién | La frase que abre el bloque |
|---|---|---|---|
| 0:00 | GitBook: 16:32 → 17:48 → 18:10 → 20:32 | A | "Setenta y seis minutos desde un login hasta la infraestructura." |
| 0:02 | Tesis: la IA cambió la economía, no los bugs | A | "El atacante ya no necesita ser sofisticado; necesita ser paciente." |
| 0:05 | Tres curvas: paciencia, precio, pesos | B | "Cada tres meses, el modelo aguanta el doble de trabajo sin que lo mires." |
| 0:12 ✂ | Pesos abiertos: 27B / 128B / 816B | A | "Cuatro máquinas. 300 W cada una. Eso no es un laboratorio: es un placard." |
| 0:18 ✂ | BigSleep: 45 vs 37; XBOW: 40k → 250k | B | "Un agente que corre una vez por día encontró más que el fuzzer." |
| 0:24 | GTG-10007 y el agente de AISI | A | "La sofisticación dejó de ser una señal confiable." |
| 0:29 ✂ | MCP, Miasma, skills; bug bounty 2,8× | B | "La superficie de ataque se mudó del código al contexto." |
| 0:35 ✂ | Cuatro controles + demo 3 min | A (B interpela) | "Si tu control de alcance vive en un PDF, no es un control." |
| 0:43 | 5 decisiones, 3 predicciones | A+B | "La IA no nos va a reemplazar. Nos va a exigir criterio." |
| 0:47 | Preguntas | ambos | — |

## Números de memoria (10)

- **45 / 37** — vulnerabilidades accionables en V8, BigSleep vs Fuzzilli, abr–sep 2026 · **25%** de solapamiento en producción.
- **40 k → 250 k** — cómputo vs recompensa de la cadena de Chrome; **6 días**, **1** investigador, **3** bugs.
- **10 / 122 · 19 acciones** — corridas de AISI con acciones fuera de alcance; **17** de un solo modelo.
- **50 organizaciones · >12 posibles 0-days/mes · 2–3 h** por brecha — GTG-10007.
- **73 repos en 105 s** — Miasma; **0 CVEs**.
- **36,8% / 13,4%** — skills con alguna falla / con fallas críticas (3.984 auditadas).
- **2,8× / 1,9×** — envíos vs reportes válidos en bug bounty desde ene 2025; **<5%** válido en curl.
- **196 / 131 / 89 días** — duplicación del horizonte temporal (histórico / ≥2023 / ≥2024).
- **36,7 tok/s** — modelo de 816B en 4 Mac Studios; **1,2 TB/s**, ~**300 W**.
- **76 min** — GitBook, sesión de staff a producción; **16 h** de caída.

## Las cuatro transiciones (ensayarlas)

1. A→B: *"Para entender por qué el precio cayó, primero hay que ver qué se compra hoy por un token."*
2. B→A: *"Los pesos salieron del data center. Y eso te toca de cerca."*
3. A→B: *"Encontrar bugs es una cosa. Convertirlos en una operación que corre sola es otra."*
4. A→B (demo): *"¿Y si el agente miente?"* — *"No puede: no escribe la evidencia."*

## Si te atrasás

- A los **24 min** seguís en XBOW → salteás el bloque de bug bounty (29–35) y pasás directo a defensas.
- A los **38 min** todavía estás en amenazas → demo reducida a una captura con `coverage=partial` y una frase: *"prefiero eso a un verde mentiroso"*.
- Nunca sacrifiques: la tesis (0:02), AISI (0:24) y las cinco decisiones (0:43).

## Reglas de escena

- Ningún número sin source ID. Si no lo sabés: *"no lo medimos"*.
- No demo contra dominios de terceros. Ni un GET.
- La demo es local; el plan B es el video.
- Una sola idea por slide. Si hay que leerla, está mal.

Barad-dûr es la consola donde un programa de seguridad guarda su inventario, su evidencia y sus decisiones. Responde cuatro preguntas con datos, no con opiniones:

- **¿Qué tenemos?** — proyectos, componentes, builds, dominios y todo lo observado sobre ellos.
- **¿Qué falta?** — la brecha entre lo que declaramos y lo que realmente analizamos.
- **¿Qué importa?** — hallazgos ordenados por exposición, no por la captura de pantalla de un escáner.
- **¿Quién decidió?** — cada autorización, aprobación y descarte queda escrito con un nombre y una hora.

Está construida para una organización que trabaja sobre su propio patrimonio. No es un SaaS y no intenta serlo.

### La regla que explica el resto del producto

**Barad-dûr decide. Shauron ejecuta.** Son dos programas, y la separación no es decorativa:

| | Barad-dûr (esta consola) | Shauron (el plano de ejecución) |
|---|---|---|
| Qué es | API, consola, base de datos | CLI, daemon, acción de CI, worker, agente de campo |
| Qué guarda | inventario, hallazgos, autorizaciones, historial, veredictos | nada permanente: un directorio de ejecución y el disco |
| Qué decide | qué se puede escanear, con qué capacidad, por quién, qué importa | qué herramienta corre cada paso, con qué versión fijada |
| Qué produce | el veredicto y el registro | el artefacto y la observación tipada |

Una herramienta en Shauron nunca sabe que la plataforma existe: escribe un archivo dentro de un directorio de ejecución, y el runner lo sube. Por eso el mismo escaneo funciona desde una laptop, desde CI y desde un contenedor worker sin una segunda implementación.

No necesitas Shauron instalado para leer esta consola. Sí necesitas que corra en algún lado para que un escaneo produzca algo.

### Qué estás mirando

La **barra lateral** es un mapa del programa, no una lista de tablas:

- las primeras filas son lo que un operador lee todos los días: **Panel**, **Mi trabajo**, **Hallazgos**, **Vulnerabilidades**, **Chat**, **Ejecuciones IA**, **Misiones**;
- **Resumen del ciclo** agrupa las tres áreas de trabajo del ciclo — *Alcance* (ciclos, alcance), *Inventario* (proyectos, activos, superficie de ataque, componentes, exposiciones) y *Priorización* (reglas, impacto de negocio);
- **Entrega** agrupa **Pipelines**, **Puertas de calidad**, **Pentests** y **Regresión**;
- **Cadena de suministro** agrupa **Builds**, **Licencias**, **Orquestación**, **Jira** y **Remediación**;
- **Ayuda → Guía** es este documento.

La **barra superior** tiene un solo buscador (`⌘K` / `Ctrl+K` le da foco) que salta a cualquier pantalla por nombre, un selector de tema, el control de identidad (con qué usuario estás firmado) y el botón de cerrar sesión. La miga debajo siempre te dice dónde estás: si dice `barad-dûr / dashboard` cuando esperabas otra pantalla, la dirección que escribiste no es una ruta.

Un botón flotante en la esquina inferior derecha abre el **asistente** — la misma pantalla de **Chat**, en un panel, para esa pregunta a la que no quieres navegar.

### Qué lees primero, todos los días

Cuatro pantallas cubren el ciclo diario, y ninguna es la historia completa:

- **Panel** abre con una frase de veredicto sobre la postura de la organización — *críticos abiertos*, *fuera de plazo* o nada urgente — y los números que la produjeron (críticos abiertos, fuera de SLA, con explotación conocida, cobertura). Debajo cuelgan el riesgo prioritario, el flujo de exposición, el portafolio por grupo y la tendencia. Si lees una sola pantalla por día, lee esta y después abre las filas que señala.
- **Mi trabajo** es el mismo patrimonio filtrado a tú: asignaciones, pedidos, tareas y aceptaciones, cada uno con su fecha límite.
- **Hallazgos** es la cola de decisiones — lo que necesita un estado y una persona.
- **Vulnerabilidades** es el catálogo: ¿este CVE famoso está en nuestro patrimonio?

Todo lo demás en la barra lateral existe para que esas cuatro valgan la pena.

**Configuración es una pantalla completa con su propia navegación**, a la que se llega desde el control de organización bajo el nombre del producto. Organización, cuenta, apariencia, entrega, inteligencia, IA e identidades de servicio viven en *Configuración del workspace*; mi seguridad, notificaciones, autorizaciones, runtime, miembros, registro de auditoría y la guía de configuración viven en *Administración*.

### Direcciones que puedes pegarle a alguien

La mayoría de las pantallas viajan en el fragmento (`#findings`, `#assets`, `#orchestration`), y un fragmento es invisible para un servidor pero funciona en un marcador y en un mensaje. Cuatro cosas tienen ruta real porque la gente las pega o recarga sobre ellas: `/projects`, `/projects/{slug}`, `/pipeline` y `/orchestration`.

Un fragmento también puede llevar el registro: `#findings::<id>`, `#asset::<id>`, `#surface::<full-run-id>`, `#components::<project>/<component>/<version>`. Usa el identificador **completo** — un prefijo acortado abre una pantalla vacía que parece rota.

### Lo que esta consola nunca va a fingir

Aprende estas tres frases temprano; son la diferencia entre un programa de seguridad y un generador de capturas de pantalla.

1. **Una tabla vacía es una pregunta, no una respuesta.** "Sin hallazgos" y "nunca analizado" son estados distintos, y las pantallas dicen cuál estás mirando: la cobertura es `full` o `partial`, con un motivo.
2. **Desconocido no es limpio.** Un componente sin datos de avisos es desconocido, no seguro.
3. **El texto del modelo no es evidencia.** Las respuestas de IA son una ayuda de lectura sobre filas que la plataforma ya tiene; un hallazgo se cierra con evidencia y una persona, nunca con un párrafo.

### Cómo usar esta guía

Lee los capítulos en orden la primera vez — siguen el orden en que llega el trabajo. Después, la columna izquierda es el índice: cada capítulo es un tema, y cada capítulo termina con las pantallas que acaba de describir, así que el documento también es un menú.

Las pantallas se nombran en **negrita** tal como las imprime la barra lateral, y los valores que escribes se muestran `like this`.

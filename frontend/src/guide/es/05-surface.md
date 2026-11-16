La superficie de ataque es la mitad del patrimonio que nadie declara: los subdominios que existen, los puertos que responden, el certificado que está por vencer, la página que revela una versión. Barad-dûr la trata como evidencia — observaciones tipadas con una fuente y una cobertura — no como un PDF de reporte de escaneo.

### Qué es un activo

Un **activo** es un dominio, subdominio, URL o IP bajo observación. Su identidad viene del sujeto que lo produjo, nunca de un nombre de archivo: una URL es un activo `url` porque empieza con un esquema, y dos filas para un mismo host significan un bug de ingesta, no una decisión de visualización.

Cuatro pestañas en **Activos**:

- **Inventario** — el árbol, con propiedad, proyecto, criticidad y cuándo se observó por última vez;
- **Observado** — las filas que escribió un colector, con fuente y cobertura;
- **Línea de tiempo / actividad** — qué cambió y cuándo;
- **Sin asignar** — activos sin proyecto, que es trabajo esperando una decisión, y se cuenta con honestidad (`showing N of M`, nunca el tamaño de página fingiendo ser el total).

La página de un activo (`#asset::<id>`) es el objeto único: resumen, certificado, **servicios agrupados por el puerto que los sirve**, la evidencia de fingerprint plegada, sus relaciones y un diálogo de escaneo precargado.

Dos reglas que las pantallas respetan, porque equivocarse en ellas le enseña a la gente a ignorar el producto:

- **La confianza necesita su propio estado.** Una sonda TLS que falló la verificación guarda un error; un certificado que falla la confianza no debe renderizarse como un certificado con fechas vacías. Imprime el motivo.
- **"Nunca observado" no es "sano".** Un punto sólido significa que respondió, uno hueco que no pudimos verlo.

### La cadena de autorización

```
declare the host  →  grant requested  →  approved in Settings → Grants
      (Scope/Assets)        (status=requested)        (level + scope + expiry)
                                                        ↓
                                            a plan may now execute on it
```

Tres cosas para internalizar:

1. **La declaración nunca elige qué se puede hacer con el host.** Ni el nivel, ni el alcance — preguntar no es autorizar. Si alguna pantalla pareciera decidir, sería un bug.
2. **El motor ignora el pedido hasta que se aprueba.** `status=requested` no autoriza nada, por construcción.
3. **Una autorización nombra un principal, un objetivo, un conjunto de capacidades y una expiración.** Un plan pregunta como el *colector*; una aprobación desde la consola registra `console`. La plataforma acepta sus dos propios principals y niega cualquier otro, así que un plan que reporta *no autorizado* mientras la tabla de Autorizaciones muestra una fila casi siempre es el objetivo o la expiración, no el principal — revisa los dos.

### Niveles de escaneo

Un nivel es un paquete de capacidades, y la capacidad es la única puerta real.

| Nivel (como se imprime) | Capacidades | Recolecta | Riesgo |
|---|---|---|---|
| escaneo simple | `passive_discovery`, `active_verification` | IPs, el certificado que sirve (emisor, validez, expiración), las tecnologías que revela la respuesta | abre una conexión TLS y lee lo que responde el servidor |
| escaneo avanzado | + `vulnerability_analysis` | todo lo de basic, más puertos abiertos, los servicios detrás y sus versiones | activo pero no intrusivo: banners, headers, puertos |
| red teaming | + `intrusive_testing` | todo lo de advanced, más descubrimiento de contenido — las rutas y archivos que expone un host | más pedidos, incluso a rutas que no existen; nunca prueba una vulnerabilidad |

El orden es una escalera: un nivel más alto contiene estrictamente al de abajo. No hay un cuarto nivel porque un cuarto no respondería una pregunta nueva.

### Perfiles: qué corre realmente

Un **perfil** es un conjunto de etapas y herramientas. La consola muestra solo los que este plano puede ejecutar, y un perfil que no puede ejecutar dice por qué en vez de desaparecer.

| Perfil | Nivel | Qué hace |
|---|---|---|
| `recon.simple` | simple | DNS → TLS → headers → tecnología. "¿Qué es este host?" |
| `web.redteam` | redteam | todo lo anterior, más puertos, servicios, versiones y descubrimiento de contenido |
| `code.sast` | — | análisis de código fuente sobre un checkout |
| `code.secrets` | — | escaneo de secretos sobre un checkout |
| `code.supply-chain` | — | SBOM más versiones de runtime |
| `image.supply-chain` | — | los paquetes y CVEs de una imagen |

Ninguno de los dos perfiles web caza vulnerabilidades. `nuclei`, `dalfox` y `sqlmap` existen en el catálogo pero no cuelgan de ningún perfil web: en el momento en que uno lo hiciera, el producto habría cambiado de categoría. El descubrimiento de contenido es lo más profundo que hace un nivel web.

### Ejecutar uno

Desde la **página del activo → escanear**, o **Orquestación → nuevo schedule** para trabajo recurrente. El diálogo pide activo, perfil y una nota de trabajo opcional; el plan lo compone el servidor y queda congelado en el job, así que la pantalla de la ejecución nunca tiene que adivinar qué se quiso decir.

Qué tiene que cumplirse para que se ejecute:

1. hay un **worker** vivo y anunciando una capacidad que el job necesita;
2. el objetivo está **cubierto por una autorización** (o la ejecución la inició un operador, lo que registra un override administrativo — salvo red team, que siempre se revalida como el colector);
3. la zona está por debajo de su **tope de concurrencia**.

Después: `queued` → `leased` → `running` → `finished` / `failed`, con los pasos reportados a medida que terminan.

### Leer una ejecución

La pantalla de la ejecución es un veredicto más la evidencia debajo:

- un **grafo de flujo derivado del plan** — las columnas son etapas, las filas son pasos, una arista donde el plan dice que se movieron datos;
- los **pasos** con `items_in` / `items_out`;
- la **traza**;
- el **diff contra la ejecución anterior** del mismo perfil sobre los mismos objetivos. DNS devuelve registros MX en cualquier orden, así que las listas se comparan como conjuntos — un diff que grita por el orden es un diff que la gente deja de leer;
- **triaje desde la ejecución**: poner el estado de un hallazgo aquí añade un evento `decision` a la misma línea de tiempo.

La **cobertura** es la frase que hay que leer primero. `full` es una afirmación sobre el perfil; un paso salteado la vuelve `partial` con el motivo. Un paso salteado nunca es una falla: una imagen que falta, una puerta que no se disparó (`wp-enum` en un host que no es WordPress), una herramienta que respondió "no aplica" — todo `skipped`.

Una ejecución de recon produce **ningún hallazgo** por diseño. Su salida son observaciones: respuestas DNS, el certificado, headers, tecnologías, puertos, servicios. Por eso la tarjeta de hallazgos puede estar vacía en una ejecución que funcionó perfecto.

### Colecciones y sus puertas

Un host con 148 subdominios no recibe un diagrama truncado: el resumen imprime el conteo real y abre la lista completa en un **panel sobre la página**, así que comparar dos filas no cuesta navegación. Cada fila lleva lo que decide cuál abrir primero — dirección, puertos y productos, días de certificado, última observación — y la fila misma es la puerta a la pantalla de esa entidad.

La misma regla vale para las relaciones: una colección recibe un conteo y una puerta, no una muestra.

### La cortesía es una fila de política

La concurrencia no está hardcodeada. Configuración → Runtime tiene una política con cuatro números:

| Ajuste | Qué limita |
|---|---|
| `per_zone` | ejecuciones contra un dominio registrable (`example.com` y todos sus subdominios comparten un bucket) |
| `per_org` | ejecuciones en vuelo para todo el workspace |
| `per_worker` | ejecuciones que puede sostener un worker |
| `queue_ceiling` | la profundidad de la cola; más allí, la creación se rechaza con `429` |

La división es deliberada: el techo rechaza **en la creación** para que el operador se entere de inmediato, mientras que los topes por zona y por org dejan una ejecución **`queued`** en el reclamo, porque rechazar ahí marcaría una política — tu propia política — como una ejecución `failed`. Seis workers apuntados a 200 subdominios de un mismo dueño es exactamente la ráfaga de egress que el tope por zona existe para evitar.

El pool de workers online se dimensiona con la misma política (`min_workers`, `max_workers`, `scale_down_after_s`). La pantalla muestra el **objetivo** al lado del conteo vivo; el proceso que lo aplica es un servicio scaler aparte, porque la API nunca debe escalar sus propios contenedores.

### Qué no es el escaneo de superficie

No es un pentest ni un escáner de vulnerabilidades sobre hosts. El trabajo intrusivo necesita una autorización **y** una decisión explícita, y la forma segura de probar que la cadena de red team funciona es un objetivo de práctica deliberadamente vulnerable, no el dominio de producción de alguien.

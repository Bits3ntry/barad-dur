Todas las pantallas usan las mismas palabras. Este capítulo es el vocabulario; si un término de otro capítulo te resulta desconocido, está definido aquí.

### Dos cadenas, un producto

La plataforma mantiene dos inventarios, y se encuentran en el medio.

**Software**: `organization → project → component → version (build) → package`. Un build llega como un SBOM CycloneDX. De ahí salen componentes, aristas de dependencia, licencias y CVEs.

**Superficie**: `asset → observation → finding`. Un activo es un host, una URL o una dirección; una observación es un hecho tipado sobre él (`dns`, `tls`, `http_headers`, `technology`, `service`, `port`, `content`); un hallazgo es la conclusión sobre la que alguien puede actuar.

Las dos cadenas responden la misma pregunta desde lados opuestos: un paquete vulnerable dentro de un build y un servicio expuesto en un host son ambos "nuestra exposición", y la consola los trata con la misma disciplina — quién lo produjo, con qué cobertura y quién decidió.

### Objetos del modelo

| Término | Qué es | Dónde lo ves |
|---|---|---|
| **Organización** | el workspace. Una base de datos, un patrimonio | el control bajo el nombre del producto |
| **Rol** | `owner`, `admin`, `analyst`, `viewer` — se muestran como Owner, Administrator, Member, Viewer | Configuración → Miembros |
| **Proyecto** | una aplicación o un producto; es dueño de componentes | **Proyectos** |
| **Componente** | una unidad de un proyecto: backend, web, mobile, una imagen | Proyectos → componentes, **Componentes** |
| **Versión / build** | un artefacto de un componente, identificado por una etiqueta y un hash de contenido | **Builds** |
| **SBOM** | un documento CycloneDX que lista qué contiene un build | Builds → filas de componentes |
| **Paquete / purl** | una dependencia y su identidad canónica (`pkg:npm/lodash@4.17.20`) | pantallas de build |
| **Activo** | un dominio, subdominio, URL o IP bajo observación | **Activos** |
| **Observación** | un hecho tipado sobre un activo, con fuente y cobertura | página del activo → evidencia |
| **Hallazgo** | la conclusión accionable: un CVE en un componente, un secreto, una debilidad de código, una exposición | **Hallazgos** |
| **Exposición** | un hallazgo sobre alcanzabilidad, no sobre un paquete | **Exposiciones** |
| **Autorización (grant)** | una autorización: un principal, un objetivo, un conjunto de capacidades, una expiración | Configuración → **Autorizaciones** |
| **Objetivo de alcance** | una declaración de propiedad; no autoriza nada | **Alcance** |
| **Zona** | el dominio registrable (`a.example.com` → `example.com`); todos los subdominios comparten un mismo bucket de concurrencia | Configuración → Runtime |
| **Ciclo** | una evaluación acotada en el tiempo: congela una referencia, no autoriza nada | **Ciclos** |
| **Puerta** | una política que decide si un build puede pasar | **Puertas de calidad** |

### Objetos de ejecución

| Término | Qué es | Dónde lo ves |
|---|---|---|
| **Capacidad** | el lenguaje del motor: `passive_discovery`, `active_verification`, `vulnerability_analysis`, `intrusive_testing` | Autorizaciones, Runtime |
| **Lane** | el lenguaje del perfil de IA: `validate`, `discover`, `exploit` | Misiones |
| **Nivel de escaneo** | un paquete de capacidades: basic / advanced / red teaming | Autorizaciones |
| **Perfil** | un conjunto nombrado de etapas y herramientas con un nivel — `recon.simple`, `web.redteam`, `code.sast`, `code.secrets`, `code.supply-chain`, `image.supply-chain` | diálogo de escaneo, Orquestación |
| **Ejecución** | una ejecución: un directorio, pasos, observaciones, cobertura | Orquestación → ejecuciones, pantalla de ejecución |
| **Paso** | una etapa de una ejecución con `items_in` / `items_out` y su propio estado | pantalla de ejecución |
| **Ticket** | el sobre firmado que autoriza una ejecución | no se muestra; es lo que hace legal a una ejecución |
| **Escáner** | el motor con nombre al que se dirige un job (`shauron-surface`) | Orquestación |
| **Worker** | el proceso que reclama y ejecuta ejecuciones en cola, y late mientras está vivo | Orquestación → workers |
| **Schedule** | "este escaneo, sobre este activo, cada N minutos" | Orquestación |
| **Escaneo interno** | los barridos propios de la plataforma: feeds de avisos, KEV/EPSS, CPEs de runtime | Orquestación → interno |
| **Pipeline** | un archivo en un repositorio que anuncia commits a la plataforma | **Pipelines** |
| **Misión** | una tarea de IA acotada con objetivos, herramientas y un presupuesto | **Misiones** |
| **Perfil de IA** | el modo bajo el que corre una pregunta: Palantír, Angmar, Morgoth | **Chat**, Misiones |
| **Ejecución LLM** | una ejecución respaldada por un modelo, con sus tokens y su costo | **Ejecuciones IA** |

### Los cuatro estados que se confunden

| Estado | Significa | Cómo se imprime |
|---|---|---|
| **absent** | miramos; no hay nada | un conjunto de filas vacío, con conteos |
| **desconocido** (`unknown`) | nunca miramos, o la fuente no tiene datos | `desconocido`, `nunca observado`, `nunca analizado` |
| **skipped** | el paso no aplicaba aquí | `skipped` con el motivo, nunca en rojo |
| **cobertura parcial** | el perfil no se ejecutó del todo | `partial` + la frase que lo explica |

Un escaneo que salteó un paso no es un escaneo fallido, y un build que nadie escaneó no es un build limpio. La consola está construida para mantenerlos separados; cuando una pantalla parece decir otra cosa, el estado honesto es el que tiene el motivo pegado.

### Leer un número

- **Los conteos en una lista son del servidor**, no de la página. `showing 200 of 268` significa que hay 268.
- **El riesgo está explicado**: el orden es peso de severidad × KEV × EPSS, con tope en 100. No es un puntaje ajustado a mano, y la pantalla lo dice donde importa.
- **`N of M components`** en una tabla filtrada significa que hay un filtro aplicado. Un puñado de filas es una porción filtrada, rara vez datos faltantes.

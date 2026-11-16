El inventario de software responde "qué entregamos y qué hay adentro". Se construye con documentos que produjo un escáner, nunca tipeados a mano.

### La cadena

`project → component → version → build`, y dentro de un build: `package → advisory → finding`.

- Un **proyecto** es la aplicación.
- Un **componente** es un entregable dentro de él (`backend`, `web`, `mobile`, `api-image`). Los componentes llevan el binding de repositorio, así que también son aquello a lo que se engancha un pipeline.
- Una **versión** agrupa builds por una etiqueta que la gente reconoce — `1.8.0`, `main`, un sha de commit.
- Un **build** es un documento CycloneDX. Volver a subir el mismo documento al mismo proyecto+versión es un no-op: la ingesta es idempotente sobre el hash de contenido.

### Crear un proyecto y sus partes

**Proyectos → nuevo proyecto** pide nombre, grupo, owner, slug y una descripción, y crea el proyecto junto con su primer componente. Desde la página del proyecto añades:

| Cosa | Por qué importa |
|---|---|
| otro **componente** | los monorepos entregan varios artefactos; cada uno se buildea por separado |
| un **repositorio** | la autorización en la que se apoya una ejecución de CI; sin eso no se puede generar ningún archivo de pipeline |
| una **versión** | agrupa builds; una versión sin build es una versión que nadie escaneó |
| un **entorno** | dónde corre — producción, staging |
| un **dominio** o un **endpoint** | la vista propia de la aplicación sobre dónde está expuesta |

Las mismas acciones existen sobre la API; la consola es un cliente, no una segunda fuente de verdad. `POST /api/v1/projects/{slug}/components` añade un componente, y el slug es lo que direcciona cualquier otra llamada.

### Meter un build — tres puertas, un resultado

**1. Desde CI (el camino normal).** Construye un pipeline, haz commit el archivo generado, sube. La CI anuncia el commit, acuña un ticket, escanea el checkout y sube el SBOM y su evidencia. Ver *Pipelines y entrega*.

**2. Desde una laptop, solo evidencia local.** El repositorio trae una CLI chica:

```sh
python3 -m venv /tmp/barad-venv
/tmp/barad-venv/bin/python -m pip install .
/tmp/barad-venv/bin/barad health
/tmp/barad-venv/bin/barad scan /path/to/project
```

`barad scan` escribe en `<workspace>/.barad/reports/<project>/<version>/<scan-id>/`: un SBOM CycloneDX de Trivy, un `security.json`, un `sast.json` de OpenGrep y un manifiesto. Nunca modifica el proyecto escaneado, y nunca sube — `security.json` y `sast.json` pueden contener secretos y fragmentos de código fuente y quedan solo para el owner.

**3. Directo contra la API.** Un documento CycloneDX JSON es el cuerpo, enviado como bytes crudos:

```sh
curl -sS -X POST \
  -H "X-API-Key: $BARAD_API_KEY" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @sbom.cdx.json \
  "http://127.0.0.1:8090/api/v1/sbom?project=aurea&component=backend&version=1.8.0"
```

El cuerpo **no** está JSON-encoded — la ruta recibe `bytes`, y un pedido `application/json` se parsea como JSON y se rechaza. `component` se puede omitir para un release de todo el producto. La respuesta es un recibo: `201` para contenido nuevo, `200` cuando ese contenido exacto ya había llegado.

**Las versiones de runtime son su propio documento.** `trivy fs` solo ve lockfiles; el intérprete está declarado, no instalado. `shauron runtime --path . --out runtime.cyclonedx.json` lee lo que declara el árbol — `engines.node`, `.nvmrc`, `requires-python`, `go.mod`, `.ruby-version`, `Dockerfile FROM` — y escribe `pkg:generic/node` o `pkg:docker/node@22-alpine`. Importalo contra el mismo project/version/component y los CVEs del runtime llegan junto a los de los paquetes. Un rango declarado sigue siendo un rango; un tag nombra una línea (`22-alpine` → la línea 22); ninguno se convierte en una versión inventada, y la confianza dice cuál es.

### Leer un build

La pantalla de un build responde, en este orden: cuántos componentes, cuántos avisos por severidad, qué dicen las licencias y qué encontró el análisis de código (SAST y secretos, incluidos los que alguien descartó — un hallazgo saldado sigue siendo un hecho sobre ese build, y ocultarlo hacía que un build escaneado se leyera como no escaneado).

Tres detalles que ahorran discusiones:

- **Un hallazgo se identifica por CVE, no por id de aviso.** Trivy nombra `CVE-2021-23337`, OSV nombra `GHSA-…` para el mismo defecto; la plataforma resuelve ambos a una sola fila.
- **Las aristas peer opcionales no son procedencia.** Que `vite` declare `@types/node` como peer no significa que el build lo haya traído. Las filas marcadas `direct` no deben imprimir "via X".
- **Los paquetes scoped conservan su scope.** Si una tabla muestra `node` donde esperabas `@types/node`, es un bug de identidad en la ingesta, no una decisión de visualización.

### Componentes vs Builds

Los dos están en la barra lateral y no son redundantes:

- **Componentes** es el catálogo entre proyectos: qué componentes existen, sus versiones, sus grupos de licencia y su riesgo, filtrable por nombre, grupo, licencia o purl. Es donde preguntas "¿quién usa esta librería?".
- **Builds** es un artefacto en detalle: los paquetes de este build, sus avisos, sus hallazgos de código y sus secretos.

### Licencias

**Licencias** agrupa por licencia lo que contienen los builds y marca las que la política prohíbe, por proyecto. Lee los mismos documentos; no hace falta subir nada extra.

### Cuando los datos se ven mal

Orden de comprobaciones, del más barato al más caro:

1. **¿Hay un filtro aplicado?** La tabla imprime `N of M`; seis filas pegadas de un build de 140 filas son un filtro, no un bug.
2. **Lee el recibo de importación.** Cada ingesta registra qué procesó — fuente, conteos, si quedó `unchanged`.
3. **Abre el documento crudo.** El artefacto subido está guardado; si un paquete no está en el documento, la ingesta no pudo inventarlo.
4. **Revisa la identidad.** El mismo paquete con dos nombres (scoped vs bare, tag vs digest) son dos filas y siempre lo fueron.

El reloj de avisos es un *segundo* reloj por encima de todo esto: después de que aterriza un build, un barrido en segundo plano vuelve a preguntarle a OSV por los builds más nuevos, refresca KEV y EPSS y cruza los runtimes contra NVD. Configuración → Inteligencia es dueña de su intervalo y sus fuentes; Orquestación muestra los barridos y sus logs. Un CVE publicado después de tu escaneo aparece por ese reloj, no porque el build haya cambiado.

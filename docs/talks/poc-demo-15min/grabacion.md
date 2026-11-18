# Guion de grabación — POC Barad-dûr + Shauron (12–15 min)

Este documento es para **grabar**, no para dar en vivo: no hay público que pregunte, así que
cada plano se puede repetir, y la narración se escribe antes de encender el micrófono.

**Objetivo del video, en una frase:** que quien lo vea entienda que Barad-dûr junta dos
cadenas que nadie junta —el código que desplegás y el host que exponés— y que cuando no sabe,
lo dice.

---

## A. Preparación técnica (una vez)

### 1 · El estado

```bash
cd ~/HUB/Workspace/Councilbox/CYB/Barad-d-r
bash scripts/poc_demo/poc_build_demo.sh
```

Tarda ~5 min y deja: proyecto `juice-shop` (2 componentes, 2 despliegues), activo
`juice-shop.demo` con 19 observaciones, `api.juice-shop.demo` sin observaciones, ~277
hallazgos, ciclo externo activo y el run de superficie terminado.

**No grabes el build.** Se graba el resultado.

### 2 · La pantalla

| Qué | Cómo |
|---|---|
| Resolución de grabación | 1920×1080 a 30 fps (o la nativa del monitor con la consola maximizada) |
| Consola | ventana 1440×900, zoom del navegador **100 %**, sin barra de marcadores |
| Terminal | 120 columnas × 30 líneas, fuente 15–16, fondo oscuro |
| Escritorio | fondo neutro, iconos ocultos, Dock auto-oculto |
| Notificaciones | **No molestar** activado (si entra un mensaje en cámara, se repite la toma) |
| Cursor | resaltado activado (OBS: "highlight cursor"; QuickTime no lo tiene) |

### 3 · El navegador

Sesión iniciada como owner. Pestañas **en el orden del guion**, para no buscar nada en cámara:

```
1  #dashboard
2  #scope
3  #grants
4  #assets
5  #projects
6  #findings
7  #cycles
8  #chat
```

Idioma de la consola en español (selector `ES` arriba a la derecha).

### 4 · La terminal

```bash
cd ~/HUB/Workspace/Councilbox/CYB/Barad-d-r
set -a; source .env; set +a
export SHAURON_PLATFORM=http://127.0.0.1:8090
clear
```

Prompt corto para que se lea en video (opcional): `export PS1='❯ '`

Comprobar antes de darle a grabar:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8090/healthz    # 200
shauron doctor | tail -3                                                   # barad reachable (200)
docker ps --format '{{.Names}}' | grep -c shauron-worker                   # 1
```

### 5 · El audio

Dos frases de prueba, escucharlas, recién ahí grabar. Ritmo de demo: **frase corta, pausa,
acción**. Silencio total mientras la pantalla hace algo (el tecleo se escucha, no se comenta
encima).

---

## B. Orden de grabación

Se graba **en el mismo orden en que se va a ver**, para que el video no tenga saltos de estado.
Las dos únicas tomas que cambian datos son:

- **T6** (el `shauron scan` del build nuevo): idempotente — si la repetís, la segunda vez dice
  "ya estaba" y no rompe nada.
- **T4** (el recon): cada toma agrega un run nuevo con sus observaciones. Se puede repetir;
  el activo acumula historial, no se rompe.

Si una toma sale mal, se repite esa toma y se sigue. No hace falta rearmar el escenario salvo
que hayas corrido el reset.

---

## C. Guion plano por plano

Cada plano trae: **pantalla**, **acción**, **narración** (texto para leer, no improvisar) y
**qué tiene que verse** (si no se ve, la toma no sirve).

---

### T1 · Apertura — `0:00` · 45 s · `#dashboard`

**Acción:** abrir la consola en `#dashboard` y no tocar nada durante las primeras dos frases.

**Narración:**
> "Esto es Barad-dûr. No es un escáner con una consola: es el registro de lo que sabemos de
> nuestro propio software y de nuestra propia superficie.
> Todo lo que ven acá se puede rastrear: cada número salió de un escaneo, con su motor, su
> versión y su cobertura. Y cuando algo no se sabe, no se inventa: se dice."

**Qué tiene que verse:** los contadores del panel (abiertos, críticos, explotados en KEV) y la
franja de "fuentes recibidas" con `trivy` y `opengrep`.

> No leas los números de memoria: señalá el número en pantalla y decí "esto es lo que hay hoy
> en esta instancia". Un número memorizado que no coincide cuesta toda la credibilidad.

---

### T2 · Permiso antes que datos — `0:45` · 1:30 · `#scope` → `#grants`

**Acción:** Alcance (los dos dominios declarados) → Autorizaciones (el grant `redteam`).

**Narración:**
> "Antes de escanear cualquier cosa: el alcance. Estos dos dominios están declarados, que
> quiere decir *conocidos*, no *autorizados*.
> La autorización es esto: un grant, con un nivel —reconocimiento profundo—, con capacidades
> concretas, con vencimiento, y con quién lo aprobó.
> Declarar un dominio no es permiso para tocarlo. Esa distinción es la que hace que esto se
> pueda usar en una empresa real."

**Qué tiene que verse:** la lista de alcance con los dos valores y, en Autorizaciones, el grant
activo con su nivel y su fecha de vencimiento.

---

### T3 · El activo y el plan — `2:15` · 2:00 · `#assets` → terminal (`shauron plan`)

**Acción:** `#assets` → abrir `juice-shop.demo` (no lanzar nada todavía) → pasar a la terminal
y correr el plan en seco.

```bash
shauron plan --profile recon.simple --target juice-shop.demo
```

**Narración (activo):**
> "Este es el escaparate: una dirección, un certificado, las tecnologías que el servidor
> declara, y diecinueve observaciones de hoy.
> Y este de al lado —la API— está declarado y sin observaciones. *Sin observaciones* no quiere
> decir limpio: quiere decir que no sabemos. Esa diferencia es el producto."

**Narración (plan):**
> "Esto es lo que el escáner haría, en seco: cuatro pasos, cada uno con la capacidad que
> necesita. No toca el host. Para que corra, cada paso tiene que caer dentro de la
> autorización que vimos recién."

**Qué tiene que verse:** la ficha del activo con dirección y tecnologías; al lado, la fila
`api.juice-shop.demo` con "sin observaciones". En la terminal, la tabla de 4 pasos con
`allow` y `4 step(s) ready`.

---

### T4 · El run y el worker — `4:15` · 2:00 · `#assets` → `#surface::<run>` → `#orchestration`

**Acción:** desde la ficha del activo, lanzar **red teaming**. Abrir el run que aparece.
Después, Orquestación.

**Narración:**
> "Lo lanzo desde acá, como lo haría un analista. La plataforma no escanea: compone el trabajo
> y lo pone en una cola.
> Esto es el run: doce pasos —DNS, puertos, servicios, tecnologías, contenido—. Uno quedó
> *dropped* y dice por qué: el host no es WordPress, así que ese paso no tenía sentido. Y la
> cobertura del TLS es *parcial* porque el certificado no es de confianza.
> Un paso que no corrió no es un paso exitoso: está escrito.
> Y acá está quién lo ejecutó: el worker, cuándo lo reclamó, hasta cuándo tiene el lease, y su
> latido. Si el latido se cae, se retira y el run vuelve a la cola."

**Qué tiene que verse:** el run con sus pasos y estados (`ok`, `dropped` con motivo,
`partial`), y en Orquestación el job con worker asignado y heartbeat.

> Si el run tarda: no narres el silencio. Mientras corre, contá qué es cada etapa —el público
> ve los pasos aparecer.

---

### T5 · El producto — `6:15` · 1:30 · `#projects` → Juice Shop → `juice-shop-web` → `1.0.0`

**Acción:** abrir el proyecto, después el componente, después la versión `1.0.0`.

**Narración:**
> "Ahora el otro lado del mismo producto. No lo que expone: lo que contiene.
> Dos componentes —el escaparate y la API—, dos repositorios vinculados, y dos despliegues.
> Producción corre la versión uno punto cero.
> Y acá está su factura de materiales: ciento cuarenta componentes, y las vulnerabilidades que
> esos componentes traen. Esto no lo dijo un humano: lo dijo el escaneo del árbol, en ese
> commit."

**Qué tiene que verse:** el proyecto con 2 componentes y 2 despliegues; dentro de
`juice-shop-web`, la versión `1.0.0` con su SBOM y sus CVE.

---

### T6 · El build nuevo — `7:45` · 2:00 · terminal → `#projects`

**Acción:** correr los dos tickets del build `1.2.0` (dejar que imprima; el JSON final se corta
en edición) y volver al proyecto.

```bash
shauron scan --project juice-shop --component juice-shop-web \
  --repository https://gitea.juice-shop.demo/juice-shop/juice-shop-web.git \
  --path ~/HUB/Workspace/Councilbox/CYB/poc-juice-shop/juice-shop-web \
  --commit 3c147ec35a0b91f1f199d61b259070de3e544eb4 \
  --version 1.2.0 --action supply-chain
```

```bash
shauron scan --project juice-shop --component juice-shop-web \
  --repository https://gitea.juice-shop.demo/juice-shop/juice-shop-web.git \
  --path ~/HUB/Workspace/Councilbox/CYB/poc-juice-shop/juice-shop-web \
  --commit 3c147ec35a0b91f1f199d61b259070de3e544eb4 \
  --version 1.2.0 --action code
```

**Narración (mientras corre):**
> "Esto es lo que dispararía el pipeline en cada push. Lo corro desde acá para no esperar al CI.
> Dos tickets, porque son dos preguntas: uno mira las dependencias, el runtime y la
> configuración; el otro mira el código. Un push no dispara todo: dispara lo que cambió.
> El commit que le paso es el sha real de ese árbol. Si el árbol y el commit no coinciden, el
> resultado miente, así que eso no se toca a mano."

**Narración (al volver al proyecto):**
> "La versión uno punto dos ya existe, con su propio inventario y sus propios hallazgos.
> Sesenta y tres, cuarenta y tres altos o críticos: subir de versión mueve el problema, no lo
> cierra.
> Y acá está lo importante: la despliego a *staging*, y producción sigue en la uno punto cero.
> Desplegar no es arreglar."

**Qué tiene que verse:** en la terminal `finished in Ns · counts {...}`; en el proyecto, la
versión `1.2.0`, el despliegue nuevo en `staging` y producción todavía en `1.0.0`.

> Si el JSON inunda la pantalla, cortá en edición justo después de la línea `finished in`.
> No uses `| tail` en la grabación: el comando tiene que verse entero.

---

### T7 · Una sola cola — `9:45` · 1:30 · `#findings`

**Acción:** filtro críticos → abrir una CVE. Después filtro "debilidad de código" → abrir el
CWE-89. Después señalar la columna de origen.

**Narración:**
> "Todo lo que vimos —el host, el producto, el build nuevo— cae acá, en una sola cola.
> Esta es una CVE de una dependencia: severidad, versión afectada, y la ruta del paquete.
> Esta otra es distinto: es una línea de código. Inyección SQL, CWE ochenta y nueve, en el
> archivo de vistas. La misma consola, dos preguntas distintas.
> Y esta columna: el origen. Escáner, pentest externo, manual. Cada fila dice quién lo dijo, y
> el escáner no borra el informe del tercero."

**Qué tiene que verse:** las dos fichas abiertas (una CVE con su paquete y versión; una
debilidad con CWE, archivo y línea) y el filtro de origen.

---

### T8 · La campaña — `11:15` · 1:00 · `#cycles`

**Acción:** abrir el ciclo `2026-Q4 · contexto externo` (ya activo), mostrar sus cuatro
hallazgos y su prueba. Después crear el barrido y vincular automático — **solo si te sobra
tiempo en el corte final**.

**Narración:**
> "Un ciclo es una ventana con alcance congelado: qué entra y qué queda afuera se decide una
> vez, y después se audita.
> Este ciclo arrancó con el informe de un pentest externo: cuatro afirmaciones, cada una con la
> petición y la respuesta que la prueban.
> Y acá está el barrido automático, que junta todo lo que la plataforma encontró sola. Dos
> fuentes, un mismo registro."

**Qué tiene que verse:** el ciclo activo con sus cuatro hallazgos y el `proof` de al menos uno;
en el barrido, el conteo de hallazgos vinculados.

---

### T9 · La IA — `12:15` · 2:00 · `#chat`

**Acción:** tres preguntas, en orden. La respuesta tarda ~30–40 s: **narrala mientras espera**,
no la dejes en silencio.

**Pregunta 1:**
> "¿Cuáles son los hallazgos CRITICAL más urgentes de juice-shop? Dame el CVE, la versión y la
> ruta, y decime qué no podés verificar."

**Narración mientras responde:**
> "Fíjense lo que hace: no contesta un párrafo. Cita filas —con su id— y dice qué le falta para
> atar cada hallazgo a un despliegue.
> Eso es lo que la vuelve usable: el texto del modelo no es evidencia; lo que la respalda, sí."

**Pregunta 2:**
> "¿El asset api.juice-shop.demo está limpio?"

**Narración:**
> "Acá está el momento que importa. No dice 'limpio'. Dice que no sabe, y qué arista falta para
> saberlo.
> Un tablero que nunca dice *unknown* está mintiendo."

**Pregunta 3:**
> "Encontrá la inyección SQL del proyecto, explicame cómo se explotaría en juice-shop.demo y
> qué evidencia tenés."

**Narración:**
> "Y acá hay que ser claros: no la está explotando. Está leyendo la evidencia que ya existe y
> diciendo qué haría falta para explotarla: una misión autorizada, con alcance y presupuesto.
> La IA propone; una persona decide."

**Qué tiene que verse:** las tres respuestas con citas a ids; en la segunda, la palabra
`unknown` (o su equivalente) y la arista faltante.

> Si el chat falla: cortá la toma, arreglá el proveedor y volvé. **No improvises una respuesta
> de IA** ni leas una respuesta vieja como si fuera nueva.

---

### T10 · Cierre — `14:15` · 30 s · `#dashboard`

**Acción:** volver al panel. Manos quietas.

**Narración (de memoria, no leer):**
> "Tres cosas, y termino.
> Las dos cadenas —un CVE en un build y un puerto expuesto— se encuentran en la misma consola.
> El modelo razona, la plataforma decide, Shauron ejecuta.
> Y cuando no sabe, lo dice."

---

## D. Qué NO decir

- ❌ "Detecta vulnerabilidades en tiempo real." → Es un escaneo, con cobertura y fecha.
- ❌ "La IA encontró esto." → La IA **lee** lo que encontró el escáner y lo que dijo el pentest.
- ❌ "Es un pentest automático." → El perfil web es reconocimiento; lo intrusivo pide grant.
- ❌ "Está limpio" sobre un activo sin observaciones. → `unknown` es la respuesta correcta.
- ❌ Cualquier número que no esté en pantalla en ese momento.
- ❌ "Esto es una demo" mientras explicás: se dice al principio y no se repite.

---

## E. Después de grabar: la lista de verificación del corte

Antes de publicar, mirar el video y confirmar que **se ve**:

- [ ] El activo con observaciones **y** el activo sin observaciones, en el mismo plano o en dos
      seguidos.
- [ ] El run con al menos un paso `dropped` y su motivo, y el worker asignado.
- [ ] La versión `1.0.0` en producción **antes** del build nuevo, y `1.0.0` **todavía** en
      producción después.
- [ ] La versión `1.2.0` en `staging`.
- [ ] Una CVE (dependencia) y un CWE (código) abiertos, cada uno con su ruta.
- [ ] La columna de origen con `pentest · externo`.
- [ ] El chat diciendo `unknown` en la segunda pregunta.
- [ ] Ningún secreto en pantalla: ni `SHAURON_BARAD_KEY`, ni `.env`, ni la terminal con el
      historial visible.

---

## F. Tomas de respaldo (si en cámara algo no coopera)

| Situación | Toma alternativa |
|---|---|
| El worker no toma el run en 10 s | mostrar `docker ps` y `docker logs --tail 5`; decirlo como estado honesto y cortar |
| El recon falla en un paso pasivo | repetir la toma; si vuelve a fallar, usar el run anterior (sigue siendo cierto, otra fecha) |
| El chat tarda demasiado | cortar la espera en edición con un fundido; nunca acelerar la respuesta |
| El `shauron scan` se corta | correrlo de nuevo: es idempotente y no duplica hallazgos |
| Se rompió el estado | `bash scripts/poc_demo/poc_build_demo.sh` y volver a grabar desde T1 |

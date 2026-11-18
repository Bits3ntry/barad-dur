# POC — Barad-dûr + Shauron sobre Juice Shop (15 minutos)

**Qué se prueba, en una frase (decirla a los 40 segundos, no repetir hasta el cierre):**

> "Barad-dûr no adivina: junta dos cadenas que nadie junta —el código que desplegás y el
> host que exponés— y cada dato que muestra lo puede rastrear a un escaneo, con su motor,
> su versión y su cobertura. Cuando no sabe, lo dice."

**Regla de la demo:** cada pantalla prueba algo que la anterior no probaba. Si no, se corta.

---

## 0. Pre-flight (la noche antes, 5 minutos)

```bash
cd ~/HUB/Workspace/Councilbox/CYB/Barad-d-r
bash scripts/poc_demo/poc_build_demo.sh      # reset + inventario + escaneos + recon (~5 min)
```

| Qué | Cuánto (hoy) |
|---|---|
| Proyecto / componentes / despliegues | 1 / 2 / 2 (ambos en `production`) |
| Hallazgos abiertos | ~277 · 32 críticos · 1 en KEV |
| Observaciones del asset | 19 (puertos, tecnologías, certificado, paths, DNS) |
| Ciclo | `2026-Q4 · contexto externo` — activo, 4 afirmaciones |

Comprobar antes de subir:

- [ ] `/healthz` → `200` · consola en `http://127.0.0.1:8092` con sesión de owner.
- [ ] `docker ps` → `barad-dur-shauron-worker-1` arriba, `juice-shop-front` publicando 80/443.
- [ ] `shauron doctor` → `barad reachable (200)`.
- [ ] Pestañas: `#dashboard` `#scope` `#grants` `#assets` `#projects` `#findings` `#cycles` `#chat`.
- [ ] Terminal en el repo con `.env` cargado y `SHAURON_PLATFORM` exportado.

---

## 1. El orden, y por qué ese orden

El recorrido es **lineal a propósito**: cada bloque consume el artefacto del anterior, así
que nunca hay que decir "esto ya lo vimos". La lógica es la de una cadena de custodia:

```
permiso → host → producto → build nuevo → una sola cola → campaña → IA
 (§2)      (§3)   (§4)          (§5)            (§6)          (§7)    (§8)
```

Si alguien pregunta "¿por qué no empezás por los hallazgos?", la respuesta está en la
primera frase: un hallazgo sin cadena es una opinión. Primero se construye el registro;
después se lee.

---

## 2. Permiso antes que datos — `1:30`

`#scope` → `#grants`

| Qué hacés | Qué se ve |
|---|---|
| Abrís Alcance: `juice-shop.demo` y `api.juice-shop.demo` declarados | el host está *declarado*, no autorizado |
| Abrís Autorizaciones: grant `redteam` a `collector`, 72 h, cuatro capacidades | lo que habilita a tocar el host |

**Frase:** "Declarar un dominio no es permiso para tocarlo. El grant es lo que habilita: nivel,
capacidades y vencimiento, con quién lo aprobó."

> Todo lo que sigue ocurre **dentro** de ese permiso. Si algo queda fuera, la consola lo dice
> con el nombre del grant con el que chocó.

## 3. El host: superficie, worker y cobertura — `4:00`

`#assets` → `juice-shop.demo` → lanzar **red teaming** → `#surface::<run>` → `#orchestration`

1. **El activo** (`#assets`): dirección `11.11.11.218`, TLS 1.3, nginx, "red teaming",
   19 observaciones. Al lado, `api.juice-shop.demo`: **sin observaciones**.
   → "Mirá este: *sin observaciones*. No dice limpio. Esa diferencia es el producto."
2. **El plan, en seco** (terminal, 20 s):
   ```bash
   shauron plan --profile recon.simple --target juice-shop.demo
   ```
   → "Esto es lo que haría. Para que corra, cada paso cae dentro de una autorización."
3. **Lanzar el profundo desde la ficha del activo** (`red teaming`) y abrir el run:
   12 pasos, uno `dropped` con su motivo (no era WordPress), TLS en `partial`.
   → "El flujo es el producto: quién lo corrió, con qué motor y versión, y qué no cubrió."
4. **Orquestación** (`#orchestration`): el job encolado, el worker que lo reclamó, el lease,
   el latido, la duración.
   → "La plataforma no escanea: compone. El worker reclama, late, y si deja de latir se retira."

**Por qué acá y no antes:** el worker no se puede explicar con la pantalla vacía; se explica
con el run que el público acaba de ver nacer.

## 4. El producto: inventario de software — `2:00`

`#projects` → **Juice Shop** → `juice-shop-web` → versión `1.0.0`

| Qué se ve | Por qué importa |
|---|---|
| 2 componentes, 2 despliegues, 2 repos vinculados, 1 activo | un producto no es un repo |
| deployment de `production` con la versión `1.0.0` | "producción" es un despliegue, no una etiqueta |
| SBOM: 140 componentes, 87 hallazgos, 51 HIGH+ | la otra cadena |

**Frase:** "Del otro lado del mismo producto: no lo que expone, lo que contiene."

## 5. El build nuevo, con el CLI — `2:30`

Terminal (esto es lo que dispararía el CI):

```bash
shauron scan --project juice-shop --component juice-shop-web \
  --repository https://gitea.juice-shop.demo/juice-shop/juice-shop-web.git \
  --path ~/HUB/Workspace/Councilbox/CYB/poc-juice-shop/juice-shop-web \
  --commit 3c147ec35a0b91f1f199d61b259070de3e544eb4 \
  --version 1.2.0 --action supply-chain
```

y el segundo ticket, con la misma forma:

```bash
shauron scan --project juice-shop --component juice-shop-web \
  --repository https://gitea.juice-shop.demo/juice-shop/juice-shop-web.git \
  --path ~/HUB/Workspace/Councilbox/CYB/poc-juice-shop/juice-shop-web \
  --commit 3c147ec35a0b91f1f199d61b259070de3e544eb4 \
  --version 1.2.0 --action code
```

Volvés a `#projects`:

1. versión `1.2.0` con **63 hallazgos, 43 HIGH+** — "3 nuevas, el resto ya estaba en el registro".
2. **nuevo despliegue**: `juice-shop-web` `1.2.0` → `staging`.
3. producción **sigue en `1.0.0`**.

**Frase:** "Subir de versión mueve el problema, no lo cierra. Y desplegar no es arreglar."

> `--action` decide el trabajo: `supply-chain` = SBOM + runtime + configuración + secretos;
> `code` = SAST + secretos. Un push dispara lo que cambió, no todo.
> `--commit` es el sha real del árbol: si no coinciden, el resultado miente.

## 6. Una sola cola — `1:30`

`#findings`

1. Filtro **críticos** → 32. Abrís una CVE (`CVE-2020-7471`, Django 2.2.0, 9.8).
2. Filtro **debilidad de código** → abrís el CWE-89 de `shop/views.py:16`.
3. Columna **origen**: `escáner`, `pentest · externo`, `manual`.

**Frase:** "Dos cadenas y tres fuentes, una sola cola. Cada fila dice quién la dijo y qué
cobertura tiene."

## 7. La campaña — `1:30`

`#cycles`

1. El ciclo `2026-Q4 · contexto externo` (activo): 4 afirmaciones de un pentest, con su
   request/response de prueba.
2. **Nuevo ciclo** `2026-Q4 · barrido`, tipo `sweep`, selección = proyecto → activar →
   **vincular hallazgos (auto)**.

**Frase:** "Un ciclo es una ventana con alcance congelado: qué entra y qué queda afuera se
decide una vez, y después se audita."

## 8. La IA — `2:00`

`#chat` — tres preguntas, en este orden:

1. **Afectación:** "¿Cuáles son los hallazgos CRITICAL más urgentes de juice-shop? Dame el CVE,
   la versión y la ruta, y decime qué no podés verificar."
   → esperado: cita ids y CVEs, y **dice qué le falta** para atar el hallazgo a un despliegue.
2. **El borde:** "¿El asset api.juice-shop.demo está limpio?"
   → esperado `unknown` + la arista que falta. Si dice "limpio", ese es el hallazgo de la charla.
3. **La debilidad:** "Encontrá la inyección SQL del proyecto, explicame cómo se explotaría en
   juice-shop.demo y qué evidencia tenés."
   → apunta a `shop/views.py:16` (CWE-89) y aclara que explotar requiere una misión con grant.

**Frase:** "Lee las mismas filas que acabás de ver. No agrega una fuente: agrega una pregunta."

> El chat corre como **Palantír** (analista). No descubre: lee el estado y re-ejecuta lo que
> ya existe.

## 9. Cierre (memorizado, 15 segundos)

1. "Las dos cadenas —un CVE en un build y un puerto expuesto— se encuentran en la misma consola."
2. "El modelo razona, la plataforma decide, Shauron ejecuta. El texto del modelo no es evidencia."
3. "Y cuando no sabe, lo dice. Un tablero que nunca dice `unknown` está mintiendo."

---

## 10. Qué cortar si vas pasado (✂)

| Minuto | Corte | Pierdes |
|---|---|---|
| 0:09 | ✂ el bloque de orquestación | el detalle del worker, no el hecho |
| 0:11 | ✂ el ciclo nuevo; mostrás el externo ya activo | el "auto-link", no la idea de ciclo |
| 0:13 | ✂ la tercera pregunta del chat | la parte de explotación |

**Nunca cortes:** alcance/grant (es la tesis), el activo con y sin observaciones (es el
`unknown`), y la última pregunta del chat.

## 11. Lo que NO prometés

- **No es un pentest automático.** El perfil web es reconocimiento; lo intrusivo pide grant y aprobación.
- **El certificado del lab es autofirmado a propósito**: el recon lo reporta "no confiable", y es cierto.
- **Región/ASN**: el activo vive en la LAN; el mapa dice "sin geolocalizador" en vez de inventar un pin.
- **Los feeds de explotación** (KEV/EPSS) dependen de la red.

## 12. Si algo se rompe

| Síntoma | Causa probable | Qué hacés |
|---|---|---|
| Un run queda `queued` | el worker no está | `docker logs --tail 20 barad-dur-shauron-worker-1`; lo mostrás como estado honesto |
| El CLI falla con `trivy-db` | mirror caído | `export TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db` y reintentás |
| El chat da error de proveedor | key o modelo | seguís: el 80% de la demo no depende del chat |
| Un paso del recon falla | fuente pasiva sin red | `bash scripts/poc_demo/run_recon.sh` |
| Todo está vacío | corriste el reset sin el seed | `bash scripts/poc_demo/poc_build_demo.sh` |

## 13. Las piezas, por si preguntan

| Pieza | Dónde vive |
|---|---|
| Los repos vulnerables | `~/HUB/Workspace/Councilbox/CYB/poc-juice-shop/juice-shop-{web,api}` (1.0.0 y 1.2.0 commiteadas) |
| El host lab | `juice-shop` (3111) + `juice-shop-front` (nginx 80/443, cert autofirmado de `juice-shop.demo`) |
| Cómo el worker resuelve el nombre | `compose.demo.yaml` → `extra_hosts: juice-shop.demo:<IP del host>` |
| Scripts (plan B) | `scripts/poc_demo/` · estado e ids en `~/…/poc-juice-shop/state.json` |
| Comandos sin envoltorio | `docs/talks/poc-demo-15min/comandos.md` |

**Ids de esta instancia** (cambian en cada `poc_build_demo.sh`; leelos de `state.json`):

- ciclo externo `5bde4228e7d64f5097ca3fb6216c9603`
- run de superficie `d3fbd024133f475799a9c2df40140990`
- CVE crítica de ejemplo `fc91c99ca4014a9c9ca6b79a66c807c9` (minimist)
- SAST CWE-89 `ad05c7fbdae542649f1c78bb33971594` (`shop/views.py:16`)
- afirmación del pentest `2762a2ef0118496488345cfd1822ef7f` (SQLi en la búsqueda)

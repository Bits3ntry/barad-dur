# RCE/DoS vía procesado de imágenes — sharp 0.34.5 / libvips 8.17.3 · Crash total del API confirmado en DEV

- **Tipo:** Bug · **Severidad:** High 6.5 · **CVSS 3.1:** AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H
- **CWE:** 787 (heap overflow en decoder) · 1104 · 400 (DoS efectivo)
- **Clasificación:** EXPLOITABLE. No es FALSE_POSITIVE ni NOT_AFFECTED.
- **Componente:** councilbox-server · `sharp@0.34.5` (`package.json:108`) con libvips embebido `8.17.3`
- **Advisories:** [GHSA-f88m-g3jw-g9cj](https://github.com/lovell/sharp/security/advisories) (libvips, fix ≥0.35.0) · GHSA-rgj7-g3m4-5g8c (libheif, fix ≥0.35.4) · GHSA-wq5f-xc86-pv6w (librsvg, fix ≥0.35.5)
- **Validado:** estático + dinámico en DEV (`api.ovac.dev.councilbox.com`, 2026-10-27). Espejo en DefectDojo: OVAC → "Compromiso ad hoc", hallazgo #176.

## Resumen

Cualquier usuario autenticado común (incluido un **participante**) provoca el **crash total del backend** con una única subida de "imagen" de 2 MB. La app valida extensión/MIME declarados, pero sharp elige el formato por **magic bytes**, así que se cuelan TIFF/SVG/HEIF/GIF craftados hasta el decoder vulnerable. Reproducido **3/3**: toda la API caída ~30 s por payload, de forma repetible. El RCE de los advisories queda como posibilidad no demostrada (condicionado a Linux glibc + node no-PIE).

## Cadena de alcance

```
UI participante ("adjuntar documento", firma)
  ↓ GraphQL addCouncilAttachment (participantsAllowed, sin checkRole)   CouncilAttachment/mutations.js:37
  ↓ filePlatform.save() → saveThumbnail(bytes crudos)                  FilePlatformNativeFS.js:87,117
  ↓ createThumbnail() → sharp(input)                                   thumbnail.js:19
  ↓ libvips 8.17.3 (dispatch por magic bytes)
  → SIGSEGV / crash del proceso node
```

**Por qué la app no lo filtra (lo que hay, por línea):**

1. `isImageFile()`/`checkValidFileType()` confían en extensión y MIME declarados por el cliente (`thumbnail.js:13-16`, `validation.js:182-194`; cualquier `image/*` se acepta).
2. En agenda interactiva, `filePlatform.save()` (→ sharp) corre **antes** de `checkValidFileType()` (`AgendaAttachment/mutations.js:112` vs `:121`): el decoder consume el payload aunque la petición luego se rechace.
3. Superficie amplia: 34 llamadas a `filePlatform.save()` en 18 módulos; el rol mínimo que llega al decoder es participante (alta de attachment REST `POST /api/agendaSignatureParticipantAttachment`, `endpoints.js:4905`).
4. `/files/upload` no llama a sharp en upload, pero con perfil FS los bytes quedan almacenados y `getThumbnail()` los decodifica lazy (`FilePlatformNativeFS.js:194`): ataque diferido.

## Evidencia (DEV)

| # | Ejecución | Resultado | API después |
|---|---|---|---|
| 1 | Control: GIF válido 1×1 como `image/png` | HTTP 200, attachment #2924 | Vivo |
| 2 | **Payload craftado** (TIFF 2,0 MB, scanline 2.147.485.696 > INT_MAX) | **HTTP 502 a ~2,8 s** (nginx: upstream muerto) | **API entera 502 ~30 s** |
| 3 | Control de tamaño: PNG válido 2,4 MB | HTTP 200 en 845 ms | Vivo |
| 4 | Repetición del payload | HTTP 502 a ~2,9 s | Caída repetida ~30 s |

- **No es rate-limit ni bloqueo por IP:** durante la caída, peticiones desde la IP del tester y desde una IP externa dan ambas 502; el rate-limiter responde 429 JSON y no aplica a sesiones autenticadas (`rateLimit.js:73,99-107`); solo 1 request por ventana.
- En macOS arm64 el mismo payload no crashea; la explotabilidad práctica depende del backend Linux (DEV/PROD).

## Reproducción

1. Autenticarse como participante (header `x-jwt-token`).
2. Lanzar la petición Burp que se deja adjunta: **`poc-sharp/burp-request-participant.txt`** (POST `/graphql` con `addCouncilAttachment`, filename `poc-sharp-impact-photo.png`, filetype `image/png`, base64 del payload TIFF). Comentar que el payload está incrustado en el .txt; no hay que montar nada más.
3. Observar 502 en ~3 s y toda la API en 502 ~30 s; recuperación automática por reinicio del supervisor.

El payload se genera con `poc-sharp/generate-payloads.mjs` (`manyband.tif`: ADOBE_DEFLATE, BitsPerSample=32, SamplesPerPixel=512, width=1048577).

## Remediación

1. **Actualizar sharp ≥ 0.35.5** (libvips 8.18.3 / libheif 1.23.2 / librsvg 2.63.2). Fix raíz, prioritario.
2. Transicional: `sharp.block({ operation: ["VipsForeignLoadSvg","VipsForeignLoadTiff","VipsForeignLoadNsgif","VipsForeignLoadHeif"] })`.
3. Validar **bytes reales** (magic sniff con `file-type`), no extensión/MIME declarados.
4. Validar el tipo **antes** de `filePlatform.save()` en todos los flujos.
5. Aislar el procesado de imágenes en un worker aparte, para que un crash no tumbe la API completa.

## Pendientes de verificación

- Confirmar root-cause en `journalctl`/`dmesg` del host DEV (SIGSEGV esperado en el instante del crash).
- Verificar PIE del binario node en PROD (`file $(which node)` + `readelf -lW $(which node) | grep GNU_RELRO`) para cerrar o confirmar la vía RCE.
- Impacto en PROD no probado; la clasificación EXTENDIBLE a PROD depende del mismo stack Linux + sharp.

*Labels sugeridos:* `security` · `owasp-a06` · `dos` · `sharp` · `libvips` · `exploitable` · `dev-validated`

> **Nota sobre adjuntos:** `burp-request-participant.txt` es un artefacto activo (reproducible tal cual). Restringir visibilidad del ticket si es posible y purgar el attachment tras la corrección.

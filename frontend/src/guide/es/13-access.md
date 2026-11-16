Quién puede hacer qué, cómo entra la gente y cómo cada decisión termina en un registro.

### Los cuatro roles

| Rol (como se imprime) | Valor en la API | Puede |
|---|---|---|
| **Owner** | `owner` | todo, incluido el workspace mismo |
| **Administrator** | `admin` | acciones administrativas: miembros, autorizaciones, políticas, entrega |
| **Member** | `analyst` | leer y escribir el conjunto de trabajo: triage, proyectos, ejecuciones |
| **Viewer** | `viewer` | solo lectura — toda escritura la rechaza la API, no la esconde la UI |

La consola muestra los nombres impresos; la API conserva los valores crudos, porque son un contrato. Un viewer nunca ve un botón deshabilitado haciendo de permiso: o el botón funciona, o la request se rechaza con una frase que nombra el rol.

**Las API keys no son un rol.** Una key se autentica como el owner del workspace y saltea los comprobaciones de rol por completo. Si necesitas un consumidor limitado, tiene que ser la cuenta de una persona — o un allowlist hecho a medida en la superficie que llama el consumidor.

**Los tokens de worker son más angostos que las keys.** Un token de worker solo puede tomar, arrancar y reportar sus propios jobs; no puede leer el estate.

### Hacer entrar a la gente

- Las **invitaciones** (Configuración → Miembros) son links de un solo uso atados a un email y a un rol. El link resuelve a `/invite` y muestra solo ese asiento: nombre de la organización, rol, el email al que se emitió.
- La **entrega por email** necesita que Configuración → Entrega esté configurado. Cuando no lo está, la pantalla te da la URL de invitación para que la pases directamente — no finge que el mail salió.
- **Crear una cuenta directamente** es para los casos donde el email no es el canal: misma pantalla, mismos roles.
- **Al último owner no se lo puede degradar ni quitar.** Eso es una protección, no un bug.

### Seguridad del inicio de sesión

| Mecanismo | Dónde se configura | Notas |
|---|---|---|
| contraseña | por persona, Configuración → Cuenta | el link de recuperación llega por mail; un admin puede entregar el código de link manual |
| multi-factor (TOTP) | Configuración → Mi seguridad | los códigos de recuperación se muestran una vez — guardalos |
| SSO | deployment (ajustes `OIDC`) | la pantalla de login pide el slug de la organización antes de poder llamar al proveedor |
| device flow (Shauron) | `shauron login` | se aprueba por una persona en `#activate::<code>`; una API key no puede aprobarlo |

### El registro de auditoría

Toda acción relevante para la seguridad se escribe en un único ledger, encadenado por organización (`chain_position`, `prev_hash`, `hash`), y eso es lo que hace la manipulación visible en lugar de apenas improbable.

Lo que queda ahí: keys creadas y revocadas, autorizaciones aprobadas y ampliadas, cambios de rol, miembros invitados y quitados, ediciones de política (escritas como el **delta** — `per_zone 2 -> 3`, no "policy updated"), y decisiones de ejecuciones.

Lo que no: las vistas de página. El ledger es un registro de cambios, no un log de sesión.

### Cuando alguien se va

1. Quita la membresía (Configuración → Miembros) — eso termina las sesiones en la siguiente llamada autenticada.
2. Revoca cualquier key emitida para esa persona o para un consumidor suyo (Configuración → Identidades de servicio).
3. Lee las últimas entradas del **Registro de auditoría** para esa identidad y mira qué tocó.
4. Si una credencial que podía leer se usó en algún lado, rotala — borrar un archivo no revoca una key, y el historial de git la conserva.

### Una separación que vale la pena mantener

- Quien **declara** un objetivo no es necesariamente quien **aprueba** la autorización. El producto está construido alrededor de esa separación; colapsarla en una sola persona es una decisión de política, y debería ser consciente.
- Quien hace **pentest** sobre un objetivo puede estar sujeto a una aprobación distinta que quien corre recon. Red team se revalida incluso detrás de un override administrativo.
- Quien hace **triage** de un hallazgo queda registrado por hallazgo y por decisión, así que "quién dijo que esto era un falso positivo" sobrevive a la rotación de personal.

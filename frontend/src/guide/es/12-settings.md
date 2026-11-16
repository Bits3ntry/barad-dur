Configuración es una pantalla completa con navegación propia, no un modal. Contiene todo lo que configura el workspace en lugar de reportar sobre él. Dos grupos, y la diferencia es a quién le pertenece cada ajuste.

### Ajustes del workspace

| Sección | Qué configura | Cuándo entrar |
|---|---|---|
| **Organización** | nombre, logo, una descripción, el sitio | la identidad del workspace está mal, o entra un equipo nuevo |
| **Cuenta** | la URL de la plataforma, la API key guardada en este navegador, inicio de sesión, cambio de contraseña, cierre de sesión | el navegador no llega a la plataforma, o necesitas reautenticarte |
| **Apariencia** | tema (dark / light / system) y densidad (comfortable / compact) | la pantalla se lee mal, o quieres más filas visibles |
| **Entrega** | el relay SMTP usado para invitaciones y notificaciones por email | las invitaciones no llegan |
| **Inteligencia** | el reloj de advisories: fuentes (OSV, CISA KEV, EPSS, NVD runtime CVEs), intervalo, tope de versiones, ejecutar ahora | quieres que aparezca un CVE publicado después del escaneo |
| **IA** | proveedores, keys selladas, precios, topes mensuales de tokens y de costo, la decisión de red team | estás cableando un modelo, o la IA se detiene por presupuesto |
| **Identidades de servicio** | API keys para automatización | un job de CI, un worker, el servidor MCP o un script necesita autenticarse |

### Administración

| Sección | Qué configura | Quién debería tenerla |
|---|---|---|
| **Mi seguridad** | autenticación multi-factor para tu propia cuenta | todos, tarde o temprano |
| **Notificaciones** | canales de entrega (Slack / webhook), suscripciones por evento, el centro in-app | quien esté de guardia |
| **Autorizaciones** | autorización del scanner: aprobar, ampliar, acortar, revocar | la persona responsable de lo que se escanea — normalmente un Administrator u Owner |
| **Runtime** | política de concurrencia de scans: por zona, por org, por worker, techo de cola, límites del pool | quien sea dueño de la relación con el objetivo |
| **Miembros** | personas, roles, invitaciones, asientos | Owner / Administrator |
| **Registro de auditoría** | las acciones de seguridad registradas, encadenadas por hash por organización | auditores. Read-only por diseño |
| **Guía de configuración** | la página de estado de seis pasos, de workspace vacío a pipeline funcionando | quien esté poniendo en marcha el workspace |

### El ajuste que todos buscan y nadie encuentra

**¿Dónde cambio qué se puede escanear?** Aquí no. Eso es **Autorizaciones** — y una autorización se aprueba a partir de una solicitud, que empieza con una declaración en **Alcance** o **Activos**. Configuración puede ampliar o revocar una autorización existente; nunca crea autoridad de la nada.

### Los dos ajustes que explican comportamientos raros

- **Inteligencia → intervalo.** El barrido de advisories decide por su cuenta si su intervalo ya pasó. Volver a llamarlo responde `not_due` y no escribe nada, así que una ejecución manual que "no hizo nada" puede simplemente haber sido temprano. La tasa de poll no es la tasa del barrido.
- **Runtime → techo de cola.** Un techo rechaza **al crear** con `429`; los topes por zona y por org dejan la ejecución `queued` en cambio. Uno es una respuesta inmediata, el otro es una espera — y ninguno de los dos es una falla.

### Apariencia y densidad, en una línea

El tema sigue al sistema operativo cuando está en *system*; la densidad cambia la escala base de fuente y los tokens de espaciado de toda la consola, así que una pantalla compacta son genuinamente más filas, no un zoom. Las dos cosas se guardan por navegador, no por cuenta.

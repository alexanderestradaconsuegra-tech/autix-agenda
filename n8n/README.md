# Backend n8n — cambios pendientes (fuera de este repo)

El frontend (`index.html` / `reservar.html`) vive en este repo, pero el backend real
(webhooks n8n en `https://n8n-n8n.fa2cjf.easypanel.host/webhook/...`) no está versionado
aquí. Los hallazgos **P0 de seguridad** de la auditoría solo se cierran si aplicas estos
cambios en n8n. El frontend ya está preparado para ellos (envía `Authorization: Bearer`
cuando existe token, y cierra sesión local si el backend responde `401`/`UNAUTHORIZED`).

## Orden de aplicación

1. **Rotar `AUTIX-2025-xK9mP3qR8nL7` ya mismo.** Está público en el HTML desde el primer
   commit del repo — asume que está filtrada. Genera una nueva y guárdala como variable
   de entorno en n8n/EasyPanel, no en el código.
2. Aplicar `agenda-auth.md` — login/registro con `bcrypt` + emisión de JWT firmado.
3. Aplicar `_shared-auth-middleware.md` como primer nodo de **todo** workflow que toque
   datos de un tenant (`agenda-clientes`, `agenda-reservas`, `agenda-movimientos`,
   `agenda-configuracion`, `agenda-servicios` (acciones no públicas), `agenda-profesionales`,
   `agenda-productos`). Esto es lo que impide que un `org_id` ajeno pase por la API_key
   compartida — hoy cualquiera puede leer/escribir datos de otro negocio.
4. Aplicar `agenda-configuracion-publica.md` — expone SOLO el nombre del negocio para
   `reservar.html`, nunca el `mp_token` ni las credenciales de WhatsApp.
5. Aplicar `agenda-mercadopago-webhook.md` — idempotencia + verificación real del pago
   contra la API de MercadoPago (nunca confiar en el `status` que llega en el body).
6. Aplicar `agenda-recordatorios-whatsapp.md` — el Schedule Trigger que de verdad envía
   los recordatorios 24h/2h que hoy son un toggle decorativo en el panel de Configuración.

## Por qué esto es P0 y no P1

Hoy, `org_id` es el mismo string que aparece público en el link de reserva
(`reservar.html?negocio=<org_id>`) y la única credencial es una API key estática igual
para todos los tenants. Cualquiera que tenga el link de reserva de un negocio (que es
público por diseño) puede llamar el webhook directo con `curl` y leer clientes, citas,
caja, y el token de MercadoPago de **ese negocio**. No es teórico: es el patrón de uso
normal de la API tal como está hoy.
